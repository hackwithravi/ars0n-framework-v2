import { useState, useEffect } from 'react';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';
import { Container, Row, Col, Button, ListGroup, Alert, Fade, Modal, Card } from 'react-bootstrap';
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

  const handleSelect = (key, value) => {
    setSelections((prev) => ({ ...prev, [key]: value }));
    setErrorMessage('');
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
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/read`);
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

  const getTypeIcon = (type) => `/images/${type}.png`;
  const getModeIcon = (mode) => `/images/${mode}.png`;

  return (
    <Container data-bs-theme="dark" className="App" style={{ padding: '20px' }}>
      <Row className="align-items-center mb-3">
        <Col xs="auto">
          <img src="/images/logo.avif" alt="Logo" style={{ height: '60px' }} />
        </Col>
        <Col xs="auto" className="ms-auto d-flex justify-content-end">
          <Button variant="link" className="text-white p-1">
            <i className="bi bi-question-circle" style={{ fontSize: '1.5rem' }}></i>
          </Button>
          <Button variant="link" className="text-white p-1">
            <i className="bi bi-person" style={{ fontSize: '1.5rem' }}></i>
          </Button>
          <Button variant="link" className="text-white p-1">
            <i className="bi bi-gear" style={{ fontSize: '1.5rem' }}></i>
          </Button>
        </Col>
      </Row>

      <AddScopeTargetModal
        show={showModal}
        handleClose={handleClose}
        selections={selections}
        handleSelect={handleSelect}
        handleFormSubmit={handleSubmit}
        errorMessage={errorMessage}
      />

      <Modal data-bs-theme="dark" show={showActiveModal} onHide={handleActiveModalClose} centered>
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Select Active Scope Target</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <ListGroup>
            {scopeTargets.map((target) => (
              <ListGroup.Item
                key={target.id}
                action
                onClick={() => handleActiveSelect(target)}
                className={activeTarget?.id === target.id ? 'bg-danger text-white' : ''}
              >
                <span>{target.scope_target}</span>
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="danger" onClick={handleDelete} className="me-auto">
            Delete
          </Button>
          <Button variant="danger" onClick={handleActiveModalClose}>
            Set Active
          </Button>
        </Modal.Footer>
      </Modal>

      {!showModal && (
        <Fade in={fadeIn}>
          <div>
            <Row className="mb-3">
              <Col>
                <h3 className="text-secondary">Scope Targets</h3>
              </Col>
              <Col className="text-end">
                <Button variant="outline-danger" onClick={handleOpen}>
                  Add Scope Target
                </Button>
                <Button variant="outline-danger" onClick={handleActiveModalOpen} className="ms-2">
                  Select Active Target
                </Button>
              </Col>
            </Row>
            <Row className="mb-3">
              <Col>
                {activeTarget && (
                  <Card variant="outline-danger">
                    <Card.Body>
                      <Card.Text className="d-flex justify-content-between text-danger">
                        <span style={{ fontSize: '22px'}}>Active Target: <strong>{activeTarget.scope_target}</strong></span>
                        <span>
                          <img src={getTypeIcon(activeTarget.type)} alt={activeTarget.type} style={{ width: '30px', marginRight: '25px' }} /> 
                          <img src={getModeIcon(activeTarget.mode)} alt={activeTarget.mode} style={{ width: '30px' }} />
                        </span>
                      </Card.Text>
                    </Card.Body>
                  </Card>
                )}
              </Col>
            </Row>
            {scopeTargets.length === 0 && (
              <Alert variant="danger" className="mt-3">
                No scope targets available. Please add a new target.
              </Alert>
            )}
          </div>
        </Fade>
      )}
    </Container>
  );
}

export default App;
