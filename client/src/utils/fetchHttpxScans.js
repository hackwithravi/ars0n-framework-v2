const fetchHttpxScans = async (activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus) => {
  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/httpx`
    );
    if (!response.ok) throw new Error('Failed to fetch httpx scans');

    const data = await response.json();
    console.log("[DEBUG] Initial HTTPX scans data:", data);
    
    const scans = data?.scans || [];
    setHttpxScans(scans);
    if (scans.length === 0) {
      console.log("[DEBUG] No HTTPX scans found");
      return null;
    }

    const mostRecentScan = scans.reduce((latest, scan) => {
      const scanDate = new Date(scan.created_at);
      return scanDate > new Date(latest.created_at) ? scan : latest;
    }, scans[0]);
    console.log("[DEBUG] Most recent scan:", mostRecentScan);

    const scanDetailsResponse = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/httpx/${mostRecentScan.scan_id}`
    );
    if (!scanDetailsResponse.ok) throw new Error('Failed to fetch httpx scan details');

    const scanDetails = await scanDetailsResponse.json();
    console.log("[DEBUG] HTTPX Scan Details:", JSON.stringify(scanDetails, null, 2));
    console.log("[DEBUG] HTTPX Result Structure:", typeof scanDetails.result, scanDetails.result);
    setMostRecentHttpxScan(scanDetails);
    setMostRecentHttpxScanStatus(scanDetails.status);

    return scanDetails;
  } catch (error) {
    console.error('Error fetching httpx scan details:', error);
  }
}

export default fetchHttpxScans; 