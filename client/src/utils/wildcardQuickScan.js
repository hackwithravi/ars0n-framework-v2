// Define the quick scan steps
const QUICK_SCAN_STEPS = {
  IDLE: 'idle',
  SUBLIST3R: 'sublist3r',
  ASSETFINDER: 'assetfinder',
  GAU: 'gau',
  CTL: 'ctl',
  SUBFINDER: 'subfinder',
  CONSOLIDATE: 'consolidate',
  HTTPX: 'httpx',
  NUCLEI_SCREENSHOT: 'nuclei-screenshot',
  METADATA: 'metadata',
  COMPLETED: 'completed'
};

// Debug utility function
const debugTrace = (message) => {
  const timestamp = new Date().toISOString();
  console.log(`[TRACE ${timestamp}] ${message}`);
};

// Helper function to wait for a scan to complete
const waitForScanCompletion = async (scanType, targetId, setIsScanning, setMostRecentScanStatus) => {
  debugTrace(`waitForScanCompletion started for ${scanType}`);
  
  // Add a hard safety timeout in case the promise never resolves
  return Promise.race([
    new Promise((resolve) => {
      const startTime = Date.now();
      const maxWaitTime = 10 * 60 * 1000; // 10 minutes maximum wait
      const hardMaxWaitTime = 15 * 60 * 1000; // 15 minutes absolute maximum
      let attempts = 0;
      
      // Add a hard timeout as safety
      const hardTimeout = setTimeout(() => {
        debugTrace(`HARD TIMEOUT: ${scanType} scan exceeded maximum wait time of 15 minutes`);
        setIsScanning(false);
        resolve({ status: 'hard_timeout', message: 'Hard scan timeout exceeded' });
      }, hardMaxWaitTime);
      
      const checkStatus = async () => {
        attempts++;
        debugTrace(`Checking ${scanType} scan status - attempt #${attempts}`);
        try {
          // Check if we've been waiting too long
          if (Date.now() - startTime > maxWaitTime) {
            debugTrace(`${scanType} scan taking too long (${Math.round((Date.now() - startTime)/1000)}s), proceeding with next step`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            return resolve({ status: 'timeout', message: 'Scan timeout exceeded' });
          }
          
          const url = `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${targetId}/scans/${scanType}`;
          debugTrace(`Fetching scan status from: ${url}`);
          
          const response = await fetch(url);
          
          if (!response.ok) {
            debugTrace(`Failed to fetch ${scanType} scan status: ${response.status} ${response.statusText}`);
            
            // If we get a 404 or other error after multiple attempts, let's proceed rather than getting stuck
            if (attempts > 10) {
              debugTrace(`${scanType} scan failed to fetch status after ${attempts} attempts, proceeding with next step`);
              setIsScanning(false);
              clearTimeout(hardTimeout); // Clear the hard timeout
              return resolve({ status: 'error', message: 'Failed to fetch scan status' });
            }
            
            // If we get a 404 or other error, we'll check again after a delay
            setTimeout(checkStatus, 5000);
            return;
          }
          
          const scans = await response.json();
          debugTrace(`Retrieved ${scans?.length || 0} ${scanType} scans`);
          
          // Handle case where there are no scans after multiple attempts
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            debugTrace(`No ${scanType} scans found, will check again`);
            
            if (attempts > 10) {
              debugTrace(`${scanType} scan returned no scans after ${attempts} attempts, proceeding with next step`);
              setIsScanning(false);
              clearTimeout(hardTimeout); // Clear the hard timeout
              return resolve({ status: 'no_scans', message: 'No scans found' });
            }
            
            setTimeout(checkStatus, 5000);
            return;
          }
          
          // Find the most recent scan
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
          
          debugTrace(`Most recent ${scanType} scan status: ${mostRecentScan.status}, ID: ${mostRecentScan.id || 'unknown'}`);
          
          // Update status in UI
          setMostRecentScanStatus(mostRecentScan.status);
          
          if (mostRecentScan.status === 'completed' || mostRecentScan.status === 'success' || mostRecentScan.status === 'failed') {
            debugTrace(`${scanType} scan finished with status: ${mostRecentScan.status}`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            resolve(mostRecentScan);
          } else {
            // Still pending, check again after delay
            debugTrace(`${scanType} scan still pending, checking again in 5 seconds`);
            setTimeout(checkStatus, 5000);
          }
        } catch (error) {
          debugTrace(`Error checking ${scanType} scan status: ${error.message}\n${error.stack}`);
          
          // If we have persistent errors after multiple attempts, proceed rather than getting stuck
          if (attempts > 10) {
            debugTrace(`${scanType} scan had persistent errors after ${attempts} attempts, proceeding with next step`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            return resolve({ status: 'persistent_error', message: 'Persistent errors checking scan status' });
          }
          
          // Don't reject immediately on errors, try again after a delay
          setTimeout(checkStatus, 5000);
        }
      };
      
      // Start checking status immediately
      checkStatus();
    }),
    // Add a separate timeout promise as a backstop
    new Promise((resolve) => {
      setTimeout(() => {
        debugTrace(`BACKUP TIMEOUT: ${scanType} scan timed out at 20 minutes absolute maximum`);
        setIsScanning(false);
        resolve({ status: 'absolute_timeout', message: 'Absolute timeout exceeded' });
      }, 20 * 60 * 1000); // 20 minutes absolute maximum
    })
  ]);
};

const startQuickScan = async (
  activeTarget,
  getQuickScanSteps,
  setIsQuickScanning,
  setQuickScanCurrentStep,
  setQuickScanTargetId,
  setIsGauScanning,
  setMostRecentGauScan,
  setMostRecentGauScanStatus,
  setIsCTLScanning,
  setMostRecentCTLScan,
  setMostRecentCTLScanStatus,
  setIsSubfinderScanning,
  setMostRecentSubfinderScan,
  setMostRecentSubfinderScanStatus,
  setIsConsolidating,
  handleConsolidate,
  setIsHttpxScanning,
  setMostRecentHttpxScan,
  setMostRecentHttpxScanStatus,
  setIsNucleiScreenshotScanning,
  setMostRecentNucleiScreenshotScan,
  setMostRecentNucleiScreenshotScanStatus,
  setIsMetaDataScanning,
  setMostRecentMetaDataScan,
  setMostRecentMetaDataScanStatus,
  startMetaDataScan,
  initiateSubfinderScan,
  initiateHttpxScan,
  initiateNucleiScreenshotScan,
  setSubfinderScans,
  setHttpxScans,
  setNucleiScreenshotScans,
  setMetaDataScans
) => {
  if (!activeTarget) return;
  
  // Clear any previous Quick Scan state
  localStorage.removeItem('quickScanCurrentStep');
  localStorage.removeItem('quickScanTargetId');
  
  setIsQuickScanning(true);
  setQuickScanCurrentStep(QUICK_SCAN_STEPS.IDLE);
  setQuickScanTargetId(activeTarget.id);
  
  localStorage.setItem('quickScanTargetId', activeTarget.id);
  localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.IDLE);
  
  try {
    const steps = getQuickScanSteps();
    
    try {
      await steps[0].action();
    } catch (error) {
      debugTrace(`Error in Sublist3r scan: ${error.message}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    try {
      await steps[1].action();
    } catch (error) {
      debugTrace(`Error in Assetfinder scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.GAU);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.GAU);
      setIsGauScanning(true);
      
      const domain = activeTarget.scope_target.replace('*.', '');

      const scanResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/gau/run`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            fqdn: domain,
            options: {
              subs: true,
              json: true,
              blacklist: ['ttf', 'woff', 'woff2', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'css'],
              providers: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
              threads: 50,
              verbose: true
            }
          }),
        }
      );
              
      if (!scanResponse.ok) {
        throw new Error(`Failed to start GAU scan: ${scanResponse.status} ${scanResponse.statusText}`);
      }
      
      const scanData = await scanResponse.json();
      
      const placeholderScan = {
        id: scanData.scan_id,
        status: 'pending',
        created_at: new Date().toISOString()
      };

      setMostRecentGauScan(placeholderScan);
      setMostRecentGauScanStatus('pending');
      
      await new Promise(resolve => setTimeout(resolve, 10000));
      
      let isGauComplete = false;
      let gauAttempts = 0;
      const maxGauAttempts = 60; // 5 minute timeout
              
      while (!isGauComplete && gauAttempts < maxGauAttempts) {
        gauAttempts++;
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
                  
        try {
          const statusResponse = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/gau`
          );
          
          if (!statusResponse.ok) {
            console.error(`Failed to fetch GAU scan status: ${statusResponse.status} ${statusResponse.statusText}`);
            continue; // Try again
          }
          
          const scans = await statusResponse.json();
          
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            continue;
          }
          
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
          
          setMostRecentGauScan(mostRecentScan);
          setMostRecentGauScanStatus(mostRecentScan.status || 'pending');
          
          if (mostRecentScan.status === 'completed' || 
              mostRecentScan.status === 'success' || 
              mostRecentScan.status === 'failed') {
            isGauComplete = true;
          }
        } catch (pollError) {
        }
      }

      
      setIsGauScanning(false);

      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in GAU scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.CTL);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.CTL);
      setIsCTLScanning(true);
      
      const domain = activeTarget.scope_target.replace('*.', '');
      
      const scanResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/ctl/run`,
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
      
      if (!scanResponse.ok) {
        console.error(`Failed to start CTL scan: ${scanResponse.status} ${scanResponse.statusText}`);
        throw new Error(`Failed to start CTL scan: ${scanResponse.status} ${scanResponse.statusText}`);
      }
      
      const scanData = await scanResponse.json();
      const placeholderScan = {
        id: scanData.scan_id,
        status: 'pending',
        created_at: new Date().toISOString()
      };
      setMostRecentCTLScan(placeholderScan);
      setMostRecentCTLScanStatus('pending');
      
      await new Promise(resolve => setTimeout(resolve, 10000));
      
      let isCtlComplete = false;
      let ctlAttempts = 0;
      const maxCtlAttempts = 60; // 5 minute timeout
      
      while (!isCtlComplete && ctlAttempts < maxCtlAttempts) {
        ctlAttempts++;
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
        
        
        try {
          const statusResponse = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/ctl`
          );
          
          if (!statusResponse.ok) {
            console.error(`Failed to fetch CTL scan status: ${statusResponse.status} ${statusResponse.statusText}`);
            continue; // Try again
          }
          
          const scans = await statusResponse.json();
          
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            continue;
          }
          
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
          
          setMostRecentCTLScan(mostRecentScan);
          setMostRecentCTLScanStatus(mostRecentScan.status || 'pending');
          
          if (mostRecentScan.status === 'completed' || 
              mostRecentScan.status === 'success' || 
              mostRecentScan.status === 'failed') {
            isCtlComplete = true;
          }
        } catch (pollError) {
        }
      }
      
      setIsCTLScanning(false);
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in CTL scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.SUBFINDER);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.SUBFINDER);
      
      await initiateSubfinderScan(
        activeTarget,
        null,
        setIsSubfinderScanning,
        setSubfinderScans,
        setMostRecentSubfinderScanStatus,
        setMostRecentSubfinderScan
      );
      
      await waitForScanCompletion(
        'subfinder',
        activeTarget.id,
        setIsSubfinderScanning,
        setMostRecentSubfinderScanStatus
      );
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Subfinder scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.CONSOLIDATE);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.CONSOLIDATE);
      setIsConsolidating(true);
      
      await handleConsolidate();
      
      setIsConsolidating(false);
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Consolidation: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.HTTPX);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.HTTPX);
      
      await initiateHttpxScan(
        activeTarget,
        null,
        setIsHttpxScanning,
        setHttpxScans,
        setMostRecentHttpxScanStatus,
        setMostRecentHttpxScan
      );
      
      await waitForScanCompletion(
        'httpx',
        activeTarget.id,
        setIsHttpxScanning,
        setMostRecentHttpxScanStatus
      );
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in HTTPX scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.NUCLEI_SCREENSHOT);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.NUCLEI_SCREENSHOT);
      
      await initiateNucleiScreenshotScan(
        activeTarget,
        null,
        setIsNucleiScreenshotScanning,
        setNucleiScreenshotScans,
        setMostRecentNucleiScreenshotScanStatus,
        setMostRecentNucleiScreenshotScan
      );
      
      await waitForScanCompletion(
        'nuclei-screenshot',
        activeTarget.id,
        setIsNucleiScreenshotScanning,
        setMostRecentNucleiScreenshotScanStatus
      );
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Nuclei Screenshot scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.METADATA);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.METADATA);
      
      await startMetaDataScan();
      
      await waitForScanCompletion(
        'metadata',
        activeTarget.id,
        setIsMetaDataScanning,
        setMostRecentMetaDataScanStatus
      );
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Metadata scan: ${error.message}`);
    }
    
    
  } catch (error) {
    debugTrace(`ERROR during manual Quick Scan: ${error.message}`);
  } finally {
    setIsQuickScanning(false);
    setQuickScanCurrentStep(QUICK_SCAN_STEPS.COMPLETED);
    localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.COMPLETED);
    debugTrace("Quick Scan session ended");
  }
};

export { startQuickScan, waitForScanCompletion, QUICK_SCAN_STEPS, debugTrace }; 