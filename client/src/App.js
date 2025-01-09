import { useState, useEffect } from 'react';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';
import SelectActiveScopeTargetModal from './modals/selectActiveScopeTargetModal.js';
import Ars0nFrameworkHeader from './components/ars0nFrameworkHeader.js';
import ManageScopeTargets from './components/manageScopeTargets.js';
import { Container, Fade, Card, Row, Col, Button, ListGroup, Accordion, Modal, Table, Form } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import fetchAmassScans from './utils/fetchAmassScans';
import initiateAmassScan from './utils/initiateAmassScan';
import monitorScanStatus from './utils/monitorScanStatus';
import validateInput from './utils/validateInput.js';
import { getTypeIcon, getModeIcon, getLastScanDate, getLatestScanStatus, getLatestScanTime, getLatestScanId } from './utils/miscUtils.js';

function App() {
  const [showScanHistoryModal, setShowScanHistoryModal] = useState(false);
  const [showRawResultsModal, setShowRawResultsModal] = useState(false);
  const [showDNSRecordsModal, setShowDNSRecordsModal] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [rawResults, setRawResults] = useState([]);
  const [dnsRecords, setDnsRecords] = useState([]);
  const [filterOptions, setFilterOptions] = useState({ A: true, CNAME: true, MX: true, TXT: true });
  const [showModal, setShowModal] = useState(false);
  const [showActiveModal, setShowActiveModal] = useState(false);
  const [selections, setSelections] = useState({
    type: '',
    mode: '',
    inputText: '',
  });
  const [scopeTargets, setScopeTargets] = useState([]);
  const [activeTarget, setActiveTarget] = useState(null);
  const [amassScans, setAmassScans] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [fadeIn, setFadeIn] = useState(false);
  const [mostRecentAmassScanStatus, setMostRecentAmassScanStatus] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScanTriggerTime, setLastScanTriggerTime] = useState(Date.now());
  const [mostRecentScanActiveTarget, setMostRecentScanActiveTarget] = useState(null)

  useEffect(() => {
    // Initial fetch of scope targets
    fetchScopeTargets();
  }, []);
  
  useEffect(() => {
    // Monitor scan status only when activeTarget is set
    if (activeTarget) {
      monitorScanStatus(
        activeTarget,
        setAmassScans,
        setIsScanning,
        setLastScanTriggerTime,
        setMostRecentAmassScanStatus
      );
    }
  }, [activeTarget]);
  
  useEffect(() => {
    // Fetch Amass scans when activeTarget changes
    if (activeTarget) {
      fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScanStatus);
    }
  }, [activeTarget]);
  
  useEffect(() => {
    // Update scan history and handle most recent scan when amassScans is updated
    if (activeTarget && amassScans.length > 0) {
      setScanHistory(amassScans);
      setMostRecentScanActiveTarget(amassScans[amassScans.length - 1]);
    }
  }, [activeTarget, amassScans]);
  
  useEffect(() => {
    // Trigger a fetch when the scan status changes to completed
    if (activeTarget && !isScanning) {
      fetchAmassScans(activeTarget, setAmassScans, setMostRecentAmassScanStatus);
    }
  }, [activeTarget, isScanning]);  

// Open Modal Handlers

  const handleOpenScanHistoryModal = () => {
    setScanHistory(amassScans)
    setShowScanHistoryModal(true);
  };

  const handleOpenRawResultsModal = () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      const rawResults = mostRecentScan.result ? mostRecentScan.result.split('\n') : [];
      setRawResults(rawResults);
      setShowRawResultsModal(true);
    } else {
      setShowRawResultsModal(true);
      console.warn("No scans available for raw results");
    }
  };

  const handleOpenDNSRecordsModal = async () => {
    if (amassScans.length > 0) {
      const mostRecentScan = amassScans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, amassScans[0]);

      try {
        const response = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${mostRecentScan.scan_id}/dns`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch DNS records');
        }
        const dnsData = await response.json();
        console.log(dnsData);
        setDnsRecords(dnsData);
        setShowDNSRecordsModal(true);
      } catch (error) {
        setShowDNSRecordsModal(true);
        console.error("Error fetching DNS records:", error);
      }
    } else {
      setShowDNSRecordsModal(true);
      console.warn("No scans available for DNS records");
    }
  };

  const handleClose = () => {
    setShowModal(false);
    setErrorMessage('');
  };

  const handleActiveModalClose = () => {
    setShowActiveModal(false);
  };

  const handleActiveModalOpen = () => {
    setShowActiveModal(true);
  };

  const handleOpen = () => {
    setSelections({ type: '', mode: '', inputText: '' });
    setShowModal(true);
  };

  const handleSubmit = async () => {
    if (!validateInput(selections, setErrorMessage)) {
      return;
    }

    if (selections.type === 'Wildcard' && !selections.inputText.startsWith('*.')) {
      setSelections((prev) => ({ ...prev, inputText: `*.${prev.inputText}` }));
    }

    if (selections.type && selections.mode && selections.inputText) {
      try {
        const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/add`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: selections.type,
            mode: selections.mode,
            scope_target: selections.inputText,
          }),
        });

        if (!response.ok) {
          throw new Error('Failed to add scope target');
        }

        setSelections({ type: '', mode: '', inputText: '' });
        setShowModal(false);
        fetchScopeTargets();
      } catch (error) {
        console.error('Error adding scope target:', error);
        setErrorMessage('Failed to add scope target');
      }
    } else {
      setErrorMessage('You forgot something...');
    }
  };

  const handleDelete = async () => {
    if (!activeTarget) return;

    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/delete/${activeTarget.id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete scope target');
      }

      setScopeTargets((prev) => {
        const updatedTargets = prev.filter((target) => target.id !== activeTarget.id);
        const newActiveTarget = updatedTargets.length > 0 ? updatedTargets[0] : null;
        setActiveTarget(newActiveTarget);
        if (!newActiveTarget && showActiveModal) {
          setShowActiveModal(false);
          setShowModal(true);
        }
        return updatedTargets;
      });
    } catch (error) {
      console.error('Error deleting scope target:', error);
    }
  };

  const fetchScopeTargets = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/read`
      );
      if (!response.ok) {
        throw new Error('Failed to fetch scope targets');
      }
      const data = await response.json();
      setScopeTargets(data || []);
      setFadeIn(true);
      if (data && data.length > 0) {
        setActiveTarget(data[0]);
      } else {
        setShowModal(true);
      }
    } catch (error) {
      console.error('Error fetching scope targets:', error);
      setScopeTargets([]);
    }
  };

  const handleActiveSelect = (target) => {
    setActiveTarget(target);
  };

  const handleSelect = (key, value) => {
    setSelections((prev) => ({ ...prev, [key]: value }));
    setErrorMessage('');
  };

  const handleCloseScanHistoryModal = () => setShowScanHistoryModal(false);
  const handleCloseRawResultsModal = () => setShowRawResultsModal(false);
  const handleCloseDNSRecordsModal = () => setShowDNSRecordsModal(false);

  const handleFilterChange = (recordType) => {
    setFilterOptions((prev) => ({ ...prev, [recordType]: !prev[recordType] }));
  };

  const startAmassScan = () => {
    initiateAmassScan(activeTarget, monitorScanStatus, setIsScanning, setAmassScans, setLastScanTriggerTime, setMostRecentAmassScanStatus)
  }

  return (
    <Container data-bs-theme="dark" className="App" style={{ padding: '20px' }}>
      <Ars0nFrameworkHeader />

      <AddScopeTargetModal
        show={showModal}
        handleClose={handleClose}
        selections={selections}
        handleSelect={handleSelect}
        handleFormSubmit={handleSubmit}
        errorMessage={errorMessage}
      />

      <SelectActiveScopeTargetModal
        showActiveModal={showActiveModal}
        handleActiveModalClose={handleActiveModalClose}
        scopeTargets={scopeTargets}
        activeTarget={activeTarget}
        handleActiveSelect={handleActiveSelect}
        handleDelete={handleDelete}
      />

      <Modal data-bs-theme="dark" show={showScanHistoryModal} onHide={handleCloseScanHistoryModal} size="xl">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Scan History</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Execution Time</th>
                <th>Number of Results</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((scan) => (
                <tr key={scan.scan_id}>
                  <td>{scan.scan_id || "ERROR"}</td>
                  <td>{scan.execution_time || "ERROR"}</td>
                  <td>{scan.result.split('\n').length || "ERROR"}</td>
                  <td>{scan.created_at || "ERROR"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Modal.Body>
      </Modal>

      <Modal data-bs-theme="dark" show={showRawResultsModal} onHide={handleCloseRawResultsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className='text-danger'>Raw Results</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <ListGroup>
            {rawResults.map((result, index) => (
              <ListGroup.Item key={index} className="text-white bg-dark">
                {result}
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Modal.Body>
      </Modal>

      <Modal data-bs-theme="dark" show={showDNSRecordsModal} onHide={handleCloseDNSRecordsModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">DNS Records</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form>
            {Object.keys(filterOptions).map((recordType) => (
              <Form.Check
                className="text-danger custom-checkbox"
                key={recordType}
                type="checkbox"
                label={recordType}
                checked={filterOptions[recordType]}
                onChange={() => handleFilterChange(recordType)}
              />
            ))}
          </Form>
          <ListGroup>
            {dnsRecords.map((record, index) => (
              <ListGroup.Item key={index}>
                {`${record}`}
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Modal.Body>
      </Modal>

      <Fade in={fadeIn}>
        <ManageScopeTargets
          handleOpen={handleOpen}
          handleActiveModalOpen={handleActiveModalOpen}
          activeTarget={activeTarget}
          scopeTargets={scopeTargets}
          getTypeIcon={getTypeIcon}
          getModeIcon={getModeIcon}
        />
      </Fade>

      {activeTarget && (
        <Fade className="mt-3" in={fadeIn}>
          <div>
            {activeTarget.type === 'Company' && (
              <div className="mb-4">
                <h3 className="text-danger">Company</h3>
                <Row>
                  <Col md={6}>
                    <Card className="mb-3 shadow-sm">
                      <Card.Body>
                        <Card.Title>Row 1, Column 1</Card.Title>
                        <Card.Text>Content for Row 1, Column 1.</Card.Text>
                      </Card.Body>
                    </Card>
                  </Col>
                  <Col md={6}>
                    <Card className="mb-3 shadow-sm">
                      <Card.Body>
                        <Card.Title>Row 1, Column 2</Card.Title>
                        <Card.Text>Content for Row 1, Column 2.</Card.Text>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <Row>
                  <Col md={12}>
                    <Card className="mb-3 shadow-sm">
                      <Card.Body>
                        <Card.Title>Row 2, Single Column</Card.Title>
                        <Card.Text>Content for Row 2, Single Column.</Card.Text>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
            {(activeTarget.type === 'Wildcard' || activeTarget.type === 'Company') && (
              <div className="mb-4">
                <h3 className="text-danger mb-3">Wildcard</h3>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column justify-content-between">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3 text-center">
                            <a href="https://github.com/OWASP/Amass" className="text-danger text-decoration-none">
                              Amass Enum
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic text-center">
                            A powerful subdomain enumeration and OSINT tool for in-depth reconnaissance.
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Last Scanned: &nbsp;&nbsp;{getLastScanDate(amassScans)}</span>
                            <span>Results: {scanHistory[scanHistory.length - 1]?.result.split('\n').length || "N/a"}</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Last Scan Status: &nbsp;&nbsp;{getLatestScanStatus(amassScans)}</span>
                            <span>Completed Scans: {scanHistory.length}</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between">
                            <span>Scan Time: &nbsp;&nbsp;{getLatestScanTime(amassScans)}</span>
                            <span>Subdomains: Coming Soon...</span>
                          </Card.Text>
                          <Card.Text className="text-white small d-flex justify-content-between mb-3">
                            <span>Scan ID: &nbsp;&nbsp;{getLatestScanId(amassScans)}</span>
                            <span>DNS Records: Coming Soon...</span>
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between w-100 mt-3 gap-2">
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenScanHistoryModal}>&nbsp;&nbsp;&nbsp;Scan History&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenRawResultsModal}>&nbsp;&nbsp;&nbsp;Raw Results&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={() => console.log(amassScans)}>Infrastructure Map</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={handleOpenDNSRecordsModal}>&nbsp;&nbsp;&nbsp;DNS Records&nbsp;&nbsp;&nbsp;</Button>
                          <Button variant="outline-danger" className="flex-fill" onClick={() => console.log(amassScans)}>&nbsp;&nbsp;&nbsp;Subdomains&nbsp;&nbsp;&nbsp;</Button>
                          <Button
                            variant="outline-danger"
                            onClick={startAmassScan}
                            disabled={isScanning || mostRecentAmassScanStatus === "pending" ? true : false}
                          >
                            {isScanning || mostRecentAmassScanStatus === "pending" ? <span className="blinking">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scanning...&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> : 'Scan ' + activeTarget.scope_target}
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Subdomain Scraping</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="row-cols-5 g-3 mb-4">
                  {[
                    { name: 'Sublist3r', link: 'https://github.com/aboul3la/Sublist3r' },
                    { name: 'Assetfinder', link: 'https://github.com/tomnomnom/assetfinder' },
                    { name: 'GAU', link: 'https://github.com/lc/gau' },
                    { name: 'CTL', link: 'https://github.com/chromium/ctlog' },
                    { name: 'Subfinder', link: 'https://github.com/projectdiscovery/subfinder' }
                  ].map((tool, index) => (
                    <Col key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            A subdomain enumeration tool that uses OSINT techniques.
                          </Card.Text>
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button variant="outline-danger" className="flex-fill">Results</Button>
                            <Button variant="outline-danger" className="flex-fill">Scan</Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Brute-Force</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="justify-content-between mb-4">
                  {[
                    { name: 'ShuffleDNS', link: 'https://github.com/projectdiscovery/shuffledns' },
                    { name: 'CeWL', link: 'https://github.com/digininja/CeWL' }
                  ].map((tool, index) => (
                    <Col md={6} className="mb-4" key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '150px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            A subdomain resolver tool that utilizes massdns for resolving subdomains.
                          </Card.Text>
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button variant="outline-danger" className="flex-fill">Results</Button>
                            <Button variant="outline-danger" className="flex-fill">Scan</Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Live Web Servers - Round 1</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm">
                      <Card.Body className="d-flex align-items-center justify-content-between">
                        <div className="d-flex flex-column">
                          <Card.Title className="text-danger fs-4 mb-2">Consolidate Subdomains</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            Each tool has discovered a list of subdomains. Now, we need to consolidate those lists into a single list of unique subdomains.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between gap-2">
                          <Button variant="outline-danger" className="flex-fill">Results</Button>
                          <Button variant="outline-danger" className="flex-fill">Consolidate</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm">
                      <Card.Body className="d-flex align-items-center justify-content-between">
                        <div className="d-flex flex-column">
                          <Card.Title className="text-danger fs-4 mb-2">Live Web Servers</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            Now that we have a list of unique subdomains, we will use{' '}
                            <a
                              href="https://github.com/projectdiscovery/httpx"
                              className="text-danger text-decoration-none"
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              httpx
                            </a>{' '}
                            by Project Discovery to identify which of those domains are pointing to live web servers.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between gap-2">
                          <Button variant="outline-danger" className="flex-fill">Results</Button>
                          <Button variant="outline-danger" className="flex-fill">Scan</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-5">JavaScript/Link Discovery</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="justify-content-between mb-4">
                  {[
                    { name: 'GoSpider', link: 'https://github.com/jaeles-project/gospider' },
                    { name: 'Subdomainizer', link: 'https://github.com/nsonaniya2010/SubDomainizer' }
                  ].map((tool, index) => (
                    <Col md={6} className="mb-4" key={index}>
                      <Card className="shadow-sm h-100 text-center" style={{ minHeight: '150px' }}>
                        <Card.Body className="d-flex flex-column">
                          <Card.Title className="text-danger mb-3">
                            <a href={tool.link} className="text-danger text-decoration-none">
                              {tool.name}
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            A fast web spider written in Go for web scraping and crawling.
                          </Card.Text>
                          <div className="d-flex justify-content-between mt-auto gap-2">
                            <Button variant="outline-danger" className="flex-fill">Results</Button>
                            <Button variant="outline-danger" className="flex-fill">Scan</Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
                <h4 className="text-secondary mb-3 fs-5">Consolidate Subdomains & Live Web Servers - Round 2</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm">
                      <Card.Body className="d-flex align-items-center justify-content-between">
                        <div className="d-flex flex-column">
                          <Card.Title className="text-danger fs-4 mb-2">Consolidate Subdomains</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            Each tool has discovered a list of subdomains. Now, we need to consolidate those lists into a single list of unique subdomains.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between gap-2">
                          <Button variant="outline-danger" className="flex-fill">Results</Button>
                          <Button variant="outline-danger" className="flex-fill">Consolidate</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm">
                      <Card.Body className="d-flex align-items-center justify-content-between">
                        <div className="d-flex flex-column">
                          <Card.Title className="text-danger fs-4 mb-2">Live Web Servers</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            Now that we have a list of unique subdomains, we will use{' '}
                            <a
                              href="https://github.com/projectdiscovery/httpx"
                              className="text-danger text-decoration-none"
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              httpx
                            </a>{' '}
                            by Project Discovery to identify which of those domains are pointing to live web servers.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between gap-2">
                          <Button variant="outline-danger" className="flex-fill">Results</Button>
                          <Button variant="outline-danger" className="flex-fill">Scan</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
                <h4 className="text-secondary mb-3 fs-3 text-center">DECISION POINT</h4>
                <Accordion data-bs-theme="dark" className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header className="fs-5">Help Me Learn!</Accordion.Header>
                    <Accordion.Body className="bg-dark">
                      <ListGroup as="ul" variant="flush">
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic one{' '}
                          <a href="https://example.com/topic1" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                          <ListGroup as="ul" variant="flush" className="mt-2">
                            <ListGroup.Item as="li" className="bg-dark text-white fst-italic">
                              Minor Topic one{' '}
                              <a href="https://example.com/minor-topic1" className="text-danger text-decoration-none">
                                Learn More
                              </a>
                            </ListGroup.Item>
                          </ListGroup>
                        </ListGroup.Item>
                        <ListGroup.Item as="li" className="bg-dark text-white">
                          Major learning topic two{' '}
                          <a href="https://example.com/topic2" className="text-danger text-decoration-none">
                            Learn More
                          </a>
                        </ListGroup.Item>
                      </ListGroup>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                <Row className="mb-4">
                  <Col>
                    <Card className="shadow-sm" style={{ minHeight: '250px' }}>
                      <Card.Body className="d-flex flex-column justify-content-between text-center">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3">Select Target URL</Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            We now have a list of unique subdomains pointing to live web servers. The next step is to take screenshots of each web application and gather data to identify the target that will give us the greatest ROI as a bug bounty hunter. Focus on signs that the target may have vulnerabilities, may not be maintained, or offers a large attack surface.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between w-100 mt-3 gap-2">
                          <Button variant="outline-danger" className="flex-fill">Take Screenshots</Button>
                          <Button variant="outline-danger" className="flex-fill">Gather Metadata</Button>
                          <Button variant="outline-danger" className="flex-fill">Generate Report</Button>
                          <Button variant="outline-danger" className="flex-fill">Select Target URL</Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                </Row>
              </div>
            )}
            {(activeTarget.type === 'Company' ||
              activeTarget.type === 'Wildcard' ||
              activeTarget.type === 'URL') && (
                <div className="mb-4">
                  <h3 className="text-danger">URL</h3>
                  <Row>
                    <Col md={12}>
                      <Card className="mb-3 shadow-sm">
                        <Card.Body>
                          <Card.Title>Row 1, Single Column</Card.Title>
                          <Card.Text>Details about the URL go here.</Card.Text>
                        </Card.Body>
                      </Card>
                    </Col>
                  </Row>
                </div>
              )}
          </div>
        </Fade>
      )}
    </Container>
  );
}

export default App;
