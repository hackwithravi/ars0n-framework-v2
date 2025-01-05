import { useState, useEffect } from 'react';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';
import SelectActiveScopeTargetModal from './modals/selectActiveScopeTargetModal.js';
import Ars0nFrameworkHeader from './components/ars0nFrameworkHeader.js';
import ManageScopeTargets from './components/manageScopeTargets.js';
import { Container, Fade, Card, Row, Col, Button, ListGroup, Accordion } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';

function App() {
  const [showModal, setShowModal] = useState(false);
  const [showActiveModal, setShowActiveModal] = useState(false);
  const [selections, setSelections] = useState({
    type: '',
    mode: '',
    inputText: '',
  });
  const [scopeTargets, setScopeTargets] = useState([]);
  const [activeTarget, setActiveTarget] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [fadeIn, setFadeIn] = useState(false);

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

  const validateInput = () => {
    const { type, inputText } = selections;

    if (type === 'Company') {
      if (!/^[a-zA-Z0-9]+$/.test(inputText)) {
        setErrorMessage('Invalid Company name. Example: Google');
        return false;
      }
    } else if (type === 'Wildcard') {
      const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (inputText.startsWith('*.') && domainRegex.test(inputText.slice(2))) {
        return true;
      }
      setErrorMessage('Invalid Wildcard format. Example: *.google.com');
      return false;
    } else if (type === 'URL') {
      const urlRegex = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!urlRegex.test(inputText)) {
        setErrorMessage('Invalid URL. Example: https://google.com');
        return false;
      }
    } else {
      setErrorMessage('Invalid selection. Please choose a type.');
      return false;
    }

    return true;
  };

  const handleSubmit = async () => {
    if (!validateInput()) {
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

  useEffect(() => {
    fetchScopeTargets();
  }, []);

  const handleSelect = (key, value) => {
    setSelections((prev) => ({ ...prev, [key]: value }));
    setErrorMessage('');
  };

  const getTypeIcon = (type) => `/images/${type}.png`;
  const getModeIcon = (mode) => `/images/${mode}.png`;

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
                      <Card.Body className="d-flex flex-column justify-content-between text-center">
                        <div>
                          <Card.Title className="text-danger fs-3 mb-3">
                            <a href="https://github.com/OWASP/Amass" className="text-danger text-decoration-none">
                              Amass
                            </a>
                          </Card.Title>
                          <Card.Text className="text-white small fst-italic">
                            A powerful subdomain enumeration and OSINT tool for in-depth reconnaissance.
                          </Card.Text>
                        </div>
                        <div className="d-flex justify-content-between w-100 mt-3 gap-2">
                          <Button variant="outline-danger" className="flex-fill">View Infrastructure Map</Button>
                          <Button variant="outline-danger" className="flex-fill">View DNS Records</Button>
                          <Button variant="outline-danger" className="flex-fill">View Subdomains</Button>
                          <Button variant="outline-danger" className="flex-fill">Scan</Button>
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
