import fetchAmassScans from './fetchAmassScans';

const monitorScanStatus = async (activeTarget, setAmassScans, setMostRecentAmassScan, setIsScanning, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains) => {
  if (!activeTarget) return;

  let status = await fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScan, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains);

  while (status === 'pending' && activeTarget) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const scanDetails = await fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScan, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains);
    status = scanDetails.status;
  }

  setIsScanning(false);
};

export default monitorScanStatus;
