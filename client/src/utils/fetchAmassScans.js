const fetchAmassScans = async (activeTarget, setAmassScans, setMostRecentAmassScanStatus) => {
  
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/amass`
      );
      if (!response.ok) throw new Error('Failed to fetch Amass scans');
  
      const data = await response.json();
      setAmassScans(data || []);
  
      if (!Array.isArray(data) || data.length === 0) return null;
  
      const mostRecentScan = data.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, data[0]);
  
      const scanDetailsResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${mostRecentScan.scan_id}`
      );
      if (!scanDetailsResponse.ok) throw new Error('Failed to fetch Amass scan details');
  
      const scanDetails = await scanDetailsResponse.json();
      setMostRecentAmassScanStatus(scanDetails.status);
      return scanDetails.status;
    } catch (error) {
      console.error('Error fetching Amass scan details:', error);
    }
  };
  export default fetchAmassScans;
  