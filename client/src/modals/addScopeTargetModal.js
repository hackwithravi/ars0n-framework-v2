import { Modal, Button, Form, Card, Row, Col } from 'react-bootstrap';
import { useEffect } from 'react';
import 'bootstrap-icons/font/bootstrap-icons.css';

function AddScopeTargetModal({ show, handleClose, selections, handleSelect, handleFormSubmit, errorMessage }) {
  useEffect(() => {
    if (show) {
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    } else {
      document.body.style.paddingRight = '';
    }

    return () => {
      document.body.style.paddingRight = '';
    };
  }, [show]);

  const getPlaceholder = () => {
    switch (selections.type) {
      case 'Company':
        return 'Example: Google';
      case 'Wildcard':
        return 'Example: *.google.com';
      case 'URL':
        return 'Example: https://hackme.google.com';
      default:
        return 'Google, *.google.com, https://hackme.google.com';
    }
  };

  const handleSubmit = () => {
    if (handleFormSubmit && typeof handleFormSubmit === 'function') {
      handleFormSubmit();
    }
  };

  const isDisabledType = (type) => ['Company', 'URL'].includes(type);
  const isDisabledMode = (mode) => ['Automated', 'Hybrid'].includes(mode);

  return (
    <Modal
      show={show}
      onHide={handleClose}
      backdrop="static"
      keyboard={false}
      animation={true}
      size="md"
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="flex-column align-items-center">
        <img
          src="/images/logo.avif"
          alt="Logo"
          style={{ width: '100px', height: '100px', marginBottom: '10px' }}
          centered
        />
        <div style={{ minHeight: '24px' }}>
          {errorMessage && (
            <p className="text-danger m-0" style={{ fontSize: '0.9rem' }}>
              {errorMessage}
            </p>
          )}
        </div>
        <Modal.Title className="w-100 text-center text-secondary-emphasis">
          Ars0n Framework v2 <span style={{ fontSize: '0.7rem' }}>beta</span>
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Row>
          {['Company', 'Wildcard', 'URL'].map((type) => (
            <Col key={type}>
              <Card
                className={`mb-3 h-200 text-center ${selections.type === type ? 'border-danger' : ''}`}
                onClick={() => !isDisabledType(type) && handleSelect('type', type)}
                style={{ 
                  cursor: isDisabledType(type) ? 'not-allowed' : 'pointer',
                  opacity: isDisabledType(type) ? 0.5 : 1,
                  pointerEvents: isDisabledType(type) ? 'none' : 'auto'
                }}
              >
                <Card.Body>
                  <img
                    src={`/images/${type}.png`}
                    alt="Logo"
                    style={{ width: '50px', height: '50px', marginBottom: '10px' }}
                    centered
                  />
                  <br />
                  {type}
                </Card.Body>
              </Card>
            </Col>
          ))}
        </Row>
        <Row>
          {['Guided', 'Automated', 'Hybrid'].map((mode) => (
            <Col key={mode}>
              <Card
                className={`mb-3 h-200 text-center ${selections.mode === mode ? 'border-danger' : ''}`}
                onClick={() => !isDisabledMode(mode) && handleSelect('mode', mode)}
                style={{ 
                  cursor: isDisabledMode(mode) ? 'not-allowed' : 'pointer',
                  opacity: isDisabledMode(mode) ? 0.5 : 1,
                  pointerEvents: isDisabledMode(mode) ? 'none' : 'auto'
                }}
              >
                <Card.Body>
                  <img
                    src={`/images/${mode}.png`}
                    alt="Logo"
                    style={{ width: '50px', height: '50px', marginBottom: '10px' }}
                    centered
                  />
                  <br />
                  {mode}
                </Card.Body>
              </Card>
            </Col>
          ))}
        </Row>
        <h5 className="text-secondary">Scope Target</h5>
        <Form.Control
          type="text"
          className="custom-input"
          placeholder={getPlaceholder()}
          value={selections.inputText}
          onChange={(e) => handleSelect('inputText', e.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              handleFormSubmit();
            }
          }}
        />
      </Modal.Body>
      <Modal.Footer>
        <Button variant="danger" onClick={handleSubmit}>
          Let's Hack!
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default AddScopeTargetModal;
