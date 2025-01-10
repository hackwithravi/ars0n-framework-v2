const getTypeIcon = (type) => `/images/${type}.png`;

const getModeIcon = (mode) => `/images/${mode}.png`;

const getExecutionTime = (execution_time) => {
    try {
        if (execution_time === " No execution time available"){
            return "---"
        }
        const minutes = execution_time.split("m")[0]
        const seconds = execution_time.split("m")[1].split(".")[0]
        if (seconds.length === 1){
            return `${minutes}:0${seconds}`
        }
        return  `${minutes}:${seconds}`
    } catch {
        return "---"
    }
}

const getResultLength = (scan) => {
    try {
        return scan.result.split('\n').length
    } catch {
        return "---"
    }
}

const getLastScanDate = (amassScans) => {
  if (amassScans.length === 0) return 'No scans available';
  const lastScan = amassScans.reduce((latest, scan) => {
    const scanDate = new Date(scan.created_at);
    return scanDate > new Date(latest.created_at) ? scan : latest;
  }, { created_at: '1970-01-01T00:00:00Z' });
  const parsedDate = new Date(lastScan.created_at);
  return isNaN(parsedDate.getTime()) ? 'Invalid scan date' : parsedDate.toLocaleString();
};

const getLatestScanStatus = (amassScans) => {
  if (amassScans.length === 0) return 'No scans available';
  const latestScan = amassScans.reduce((latest, scan) => {
    return new Date(scan.created_at) > new Date(latest.created_at) ? scan : latest;
  }, amassScans[0]);
  return latestScan.status || 'No status available';
};

const getLatestScanTime = (amassScans) => {
  if (amassScans.length === 0) return 'No scans available';
  const latestScan = amassScans.reduce((latest, scan) => {
    return new Date(scan.created_at) > new Date(latest.created_at) ? scan : latest;
  }, amassScans[0]);
  return latestScan.execution_time || 'No execution time available';
};

const getLatestScanId = (amassScans) => {
  if (amassScans.length === 0) return 'No scans available';
  const latestScan = amassScans.reduce((latest, scan) => {
    return new Date(scan.created_at) > new Date(latest.created_at) ? scan : latest;
  }, amassScans[0]);
  return latestScan.scan_id || 'No scan ID available';
};

export { getTypeIcon, getModeIcon, getLastScanDate, getLatestScanStatus, getLatestScanTime, getLatestScanId, getExecutionTime, getResultLength };
