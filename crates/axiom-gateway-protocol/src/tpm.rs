use crate::PCR_SELECTION;
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .context("evidence offset overflow")?;
        let out = self
            .input
            .get(self.offset..end)
            .context("truncated TPM evidence")?;
        self.offset = end;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into()?))
    }
    fn le16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into()?))
    }
    fn le32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into()?))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.bytes(len)
    }
}

pub(crate) fn verify_quote(
    quote: &[u8],
    nonce: &[u8; 32],
    pcrs: &BTreeMap<u8, String>,
) -> Result<()> {
    let mut r = Reader::new(quote);
    ensure!(
        r.u32()? == 0xff54_4347 && r.u16()? == 0x8018,
        "not a TPM quote"
    );
    r.sized()?; // qualified signer; identity is established by the verified AK signature.
    ensure!(r.sized()? == nonce, "TPM challenge/key binding mismatch");
    r.bytes(16)?; // clock, resetCount, restartCount
    ensure!(r.bytes(1)? == [1], "unsafe TPM clock");
    r.bytes(8)?; // firmwareVersion
    ensure!(
        r.u32()? == 1 && r.u16()? == 0x000b,
        "unexpected PCR bank selection"
    );
    let size = usize::from(r.bytes(1)?[0]);
    ensure!(size == 3, "unexpected PCR bitmap");
    let bitmap = r.bytes(size)?;
    let mut expected = [0_u8; 3];
    for pcr in PCR_SELECTION {
        expected[usize::from(pcr / 8)] |= 1 << (pcr % 8);
    }
    ensure!(bitmap == expected, "unexpected PCR selection");
    let digest = r.sized()?;
    let mut combined = Sha256::new();
    for pcr in PCR_SELECTION {
        let value = hex::decode(pcrs.get(&pcr).context("missing PCR")?)?;
        ensure!(
            value.len() == 32 && (pcr == 12 || value != [0; 32]),
            "invalid or empty PCR value"
        );
        combined.update(value);
    }
    ensure!(
        digest == combined.finalize().as_slice() && r.offset == quote.len(),
        "PCR digest mismatch"
    );
    Ok(())
}

pub(crate) fn verify_event_log(log: &[u8], pcrs: &BTreeMap<u8, String>) -> Result<()> {
    let mut r = Reader::new(log);
    // The initial legacy-format EV_NO_ACTION contains the algorithm-size table.
    ensure!(
        r.le32()? == 0 && r.le32()? == 3,
        "missing TCG Spec ID event"
    );
    r.bytes(20)?;
    let size = usize::try_from(r.le32()?)?;
    let spec = r.bytes(size)?;
    let mut s = Reader::new(spec);
    ensure!(s.bytes(16)? == b"Spec ID Event03\0", "unsupported boot log");
    s.bytes(8)?; // platform class and version fields
    let count = s.le32()?;
    ensure!((1..=8).contains(&count), "invalid algorithm count");
    let mut algorithms = BTreeMap::new();
    for _ in 0..count {
        let alg = s.le16()?;
        let size = usize::from(s.le16()?);
        let expected = match alg {
            4 => 20,
            11 => 32,
            12 => 48,
            13 => 64,
            _ => anyhow::bail!("unsupported log digest"),
        };
        ensure!(
            size == expected && algorithms.insert(alg, size).is_none(),
            "invalid log algorithms"
        );
    }
    ensure!(algorithms.contains_key(&11), "missing SHA-256 boot log");
    let vendor_size = usize::from(s.bytes(1)?[0]);
    s.bytes(vendor_size)?;
    ensure!(s.offset == spec.len(), "invalid Spec ID length");
    let mut replay: BTreeMap<_, _> = PCR_SELECTION.into_iter().map(|v| (v, [0_u8; 32])).collect();
    let mut events = 0;
    while r.offset < log.len() {
        events += 1;
        ensure!(events <= 16384, "boot log has too many events");
        let pcr = r.le32()?;
        ensure!(pcr <= 23, "invalid log PCR index");
        let kind = r.le32()?;
        let count = r.le32()?;
        ensure!((1..=8).contains(&count), "invalid event digest count");
        let mut digest = None;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let alg = r.le16()?;
            ensure!(seen.insert(alg), "duplicate event digest");
            let size = *algorithms
                .get(&alg)
                .context("unregistered digest algorithm")?;
            let bytes = r.bytes(size)?;
            if alg == 11 {
                digest = Some(bytes);
            }
        }
        let size = usize::try_from(r.le32()?)?;
        r.bytes(size)?;
        if kind != 3
            && let Some(current) = replay.get_mut(&u8::try_from(pcr)?)
        {
            let digest = digest.context("missing event SHA-256 digest")?;
            *current = Sha256::digest([current.as_slice(), digest].concat()).into();
        }
    }
    for (pcr, value) in replay {
        ensure!(
            pcrs.get(&pcr) == Some(&hex::encode(value)),
            "boot log replay mismatch"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_log() -> (Vec<u8>, BTreeMap<u8, String>) {
        let mut spec = b"Spec ID Event03\0".to_vec();
        spec.extend_from_slice(&[0; 8]);
        spec.extend_from_slice(&1_u32.to_le_bytes());
        spec.extend_from_slice(&11_u16.to_le_bytes());
        spec.extend_from_slice(&32_u16.to_le_bytes());
        spec.push(0);
        let mut log = 0_u32.to_le_bytes().to_vec();
        log.extend_from_slice(&3_u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&u32::try_from(spec.len()).unwrap().to_le_bytes());
        log.extend(spec);
        let mut pcrs = BTreeMap::new();
        for pcr in PCR_SELECTION {
            let digest = [pcr; 32];
            log.extend_from_slice(&u32::from(pcr).to_le_bytes());
            log.extend_from_slice(&13_u32.to_le_bytes());
            log.extend_from_slice(&1_u32.to_le_bytes());
            log.extend_from_slice(&11_u16.to_le_bytes());
            log.extend_from_slice(&digest);
            log.extend_from_slice(&0_u32.to_le_bytes());
            pcrs.insert(
                pcr,
                hex::encode(Sha256::digest([&[0; 32], digest.as_slice()].concat())),
            );
        }
        (log, pcrs)
    }

    fn quote(nonce: &[u8; 32], pcrs: &BTreeMap<u8, String>) -> Vec<u8> {
        let mut raw = 0xff54_4347_u32.to_be_bytes().to_vec();
        raw.extend_from_slice(&0x8018_u16.to_be_bytes());
        raw.extend_from_slice(&0_u16.to_be_bytes());
        raw.extend_from_slice(&32_u16.to_be_bytes());
        raw.extend_from_slice(nonce);
        raw.extend_from_slice(&[0; 16]);
        raw.push(1);
        raw.extend_from_slice(&[0; 8]);
        raw.extend_from_slice(&1_u32.to_be_bytes());
        raw.extend_from_slice(&11_u16.to_be_bytes());
        raw.extend_from_slice(&[3, 0x90, 0x18, 0]);
        let mut digest = Sha256::new();
        for pcr in PCR_SELECTION {
            digest.update(hex::decode(&pcrs[&pcr]).unwrap());
        }
        raw.extend_from_slice(&32_u16.to_be_bytes());
        raw.extend_from_slice(&digest.finalize());
        raw
    }

    #[test]
    fn log_replay_and_nonce_bound_quote_reject_substitution() {
        let (log, mut pcrs) = boot_log();
        let nonce = [7; 32];
        let raw = quote(&nonce, &pcrs);
        assert!(verify_event_log(&log, &pcrs).is_ok());
        assert!(verify_quote(&raw, &nonce, &pcrs).is_ok());
        assert!(verify_quote(&raw, &[8; 32], &pcrs).is_err());
        assert!(verify_quote(&raw[..raw.len() - 1], &nonce, &pcrs).is_err());
        assert!(verify_event_log(&log[..log.len() - 1], &pcrs).is_err());
        pcrs.insert(11, "00".repeat(32));
        assert!(verify_quote(&raw, &nonce, &pcrs).is_err());
        assert!(verify_event_log(&log, &pcrs).is_err());
    }
}
