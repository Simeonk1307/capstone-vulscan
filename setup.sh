echo "Creating old_src directory (if it does not exist)"
mkdir -p ./old_src

echo "Unzipping ./vulscan-001.zip to old_src"
unzip -d old_src ./vulscan-001.zip

echo "Unzipping ./VulScan-20260408T110254Z-3-002.zip to old_src"
unzip -d old_src ./VulScan-20260408T110254Z-3-002.zip

echo "Unzipping ./old_src/VulScan/vulscan_deliverables.zip in old_src/VulScan"
unzip -d ./old_src/VulScan ./old_src/VulScan/vulscan_deliverables.zip