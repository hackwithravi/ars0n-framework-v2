import fetchAmassScans from './fetchAmassScans';

const monitorScanStatus = async (activeTarget, setAmassScans, setIsScanning, setLastScanTriggerTime, setMostRecentAmassScanStatus) => {
  if (!activeTarget) return;

  let status = await fetchAmassScans(activeTarget, activeTarget, setAmassScans, setMostRecentAmassScanStatus);

  while (status === 'pending' && activeTarget) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    status = await fetchAmassScans(activeTarget, activeTarget, setAmassScans, setMostRecentAmassScanStatus);
  }

  setIsScanning(false);
  setLastScanTriggerTime(Date.now());
};

export default monitorScanStatus;
