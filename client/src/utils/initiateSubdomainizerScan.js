const initiateSubdomainizerScan = async (
  activeTarget,
  monitorSubdomainizerScanStatus,
  setIsSubdomainizerScanning,
  setSubdomainizerScans,
  setMostRecentSubdomainizerScanStatus,
  setMostRecentSubdomainizerScan
) => {
  if (!activeTarget || !activeTarget.scope_target) {
    console.error('No active target or invalid target format');
    return;
  }

  const domain = activeTarget.scope_target.replace('*.', '');
  if (!domain) {
    console.error('Invalid domain');
    return;
  }

  try {
    setIsSubdomainizerScanning(true);
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/subdomainizer/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fqdn: domain
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to initiate Subdomainizer scan: ${errorText}`);
    }

    const data = await response.json();

    monitorSubdomainizerScanStatus(
      activeTarget,
      setSubdomainizerScans,
      setMostRecentSubdomainizerScan,
      setIsSubdomainizerScanning,
      setMostRecentSubdomainizerScanStatus
    );

    return data;
  } catch (error) {
    console.error('Error initiating Subdomainizer scan:', error);
    setIsSubdomainizerScanning(false);
    setMostRecentSubdomainizerScan(null);
    setMostRecentSubdomainizerScanStatus(null);
  }
};

export default initiateSubdomainizerScan; 