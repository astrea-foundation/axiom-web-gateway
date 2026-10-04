targetScope = 'resourceGroup'

param location string = resourceGroup().location
param name string = 'axiom-gateway-dev'
@description('Existing Specialized Gen2 Compute Gallery image version built from gateway.vhd, with the signing certificate enrolled in UEFI DB.')
param galleryImageVersionId string
@description('Intel TDX DCesv5 SKU available in this region; AMD and ordinary VMs fail attestation.')
@allowed(['Standard_DC2es_v5', 'Standard_DC4es_v5', 'Standard_DC8es_v5', 'Standard_DC16es_v5', 'Standard_DC32es_v5'])
param vmSize string = 'Standard_DC4es_v5'
@description('Only the first-party HTTPS edge may reach the encrypted gateway listener.')
param edgeSourceCidr string
param subnetId string

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${name}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'encrypted-gateway-from-edge'
        properties: { priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp', sourceAddressPrefix: edgeSourceCidr, sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '8080' }
      }
      {
        name: 'deny-other-inbound'
        properties: { priority: 200, direction: 'Inbound', access: 'Deny', protocol: '*', sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*' }
      }
    ]
  }
}
resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${name}-nic'
  location: location
  properties: {
    networkSecurityGroup: { id: nsg.id }
    ipConfigurations: [{ name: 'private', properties: { subnet: { id: subnetId }, privateIPAllocationMethod: 'Dynamic' } }]
  }
}
resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' = {
  name: name
  location: location
  properties: {
    hardwareProfile: { vmSize: vmSize }
    securityProfile: { securityType: 'ConfidentialVM', uefiSettings: { secureBootEnabled: true, vTpmEnabled: true } }
    storageProfile: {
      imageReference: { id: galleryImageVersionId }
      osDisk: { createOption: 'FromImage', caching: 'ReadOnly', managedDisk: { storageAccountType: 'Standard_LRS', securityProfile: { securityEncryptionType: 'VMGuestStateOnly' } } }
    }
    // Specialized appliance: no agent, credentials or mutable provisioning.
    networkProfile: { networkInterfaces: [{ id: nic.id }] }
    diagnosticsProfile: { bootDiagnostics: { enabled: false } }
  }
}
output privateAddress string = nic.properties.ipConfigurations[0].properties.privateIPAddress
output vmId string = vm.id
