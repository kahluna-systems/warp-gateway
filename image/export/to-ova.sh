#!/bin/bash
# ============================================================================
# Export WARP OS raw image to OVA (VMware)
# Usage: to-ova.sh <input.img> <output.ova>
# ============================================================================
set -euo pipefail

INPUT="$1"
OUTPUT="$2"
WORK_DIR=$(mktemp -d)
VM_NAME="warp-os"

echo "Converting raw image to OVA: $OUTPUT"

# Check for qemu-img
if ! command -v qemu-img &>/dev/null; then
    echo "ERROR: qemu-img not found. Install with: sudo apt install qemu-utils"
    exit 1
fi

# Convert raw to VMDK
echo "Converting to VMDK..."
VMDK="$WORK_DIR/${VM_NAME}-disk1.vmdk"
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "$INPUT" "$VMDK"

# Create OVF descriptor
DISK_SIZE=$(stat -c%s "$INPUT")
VMDK_SIZE=$(stat -c%s "$VMDK")

cat > "$WORK_DIR/${VM_NAME}.ovf" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">
  <References>
    <File ovf:href="${VM_NAME}-disk1.vmdk" ovf:id="file1" ovf:size="$VMDK_SIZE"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="$DISK_SIZE" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystemCollection ovf:id="${VM_NAME}">
    <VirtualSystem ovf:id="${VM_NAME}">
      <Info>KahLuna WARP Gateway Appliance</Info>
      <Name>${VM_NAME}</Name>
      <OperatingSystemSection ovf:id="96">
        <Info>Ubuntu 64-bit</Info>
      </OperatingSystemSection>
      <VirtualHardwareSection>
        <Info>Virtual hardware requirements</Info>
        <System>
          <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
          <vssd:InstanceID>0</vssd:InstanceID>
          <vssd:VirtualSystemType>vmx-13</vssd:VirtualSystemType>
        </System>
        <Item>
          <rasd:Description>Number of Virtual CPUs</rasd:Description>
          <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
          <rasd:InstanceID>1</rasd:InstanceID>
          <rasd:ResourceType>3</rasd:ResourceType>
          <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
        </Item>
        <Item>
          <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
          <rasd:Description>Memory Size</rasd:Description>
          <rasd:ElementName>2048MB of memory</rasd:ElementName>
          <rasd:InstanceID>2</rasd:InstanceID>
          <rasd:ResourceType>4</rasd:ResourceType>
          <rasd:VirtualQuantity>2048</rasd:VirtualQuantity>
        </Item>
        <Item>
          <rasd:AddressOnParent>0</rasd:AddressOnParent>
          <rasd:ElementName>Hard Disk 1</rasd:ElementName>
          <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
          <rasd:InstanceID>3</rasd:InstanceID>
          <rasd:ResourceType>17</rasd:ResourceType>
        </Item>
        <Item>
          <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
          <rasd:Connection>VM Network</rasd:Connection>
          <rasd:Description>WAN Interface</rasd:Description>
          <rasd:ElementName>Network adapter 1</rasd:ElementName>
          <rasd:InstanceID>4</rasd:InstanceID>
          <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
          <rasd:ResourceType>10</rasd:ResourceType>
        </Item>
        <Item>
          <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
          <rasd:Connection>VM Network</rasd:Connection>
          <rasd:Description>LAN Interface</rasd:Description>
          <rasd:ElementName>Network adapter 2</rasd:ElementName>
          <rasd:InstanceID>5</rasd:InstanceID>
          <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
          <rasd:ResourceType>10</rasd:ResourceType>
        </Item>
      </VirtualHardwareSection>
    </VirtualSystem>
  </VirtualSystemCollection>
</Envelope>
EOF

# Create OVA (tar archive of OVF + VMDK)
echo "Packaging OVA..."
(cd "$WORK_DIR" && tar -cf "$OUTPUT" "${VM_NAME}.ovf" "${VM_NAME}-disk1.vmdk")

rm -rf "$WORK_DIR"
echo "OVA created: $OUTPUT"
ls -lh "$OUTPUT"
