import { Modal, Button, Form, Card, Row, Col } from 'react-bootstrap';

function AddScopeTargetModal({ show, handleClose, selections, handleSelect, handleSubmit }) {
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
      <Modal.Header className="flex-column align-items-center">
        <img
          src="/images/logo.avif"
          alt="Logo"
          style={{ width: '100px', height: '100px', marginBottom: '10px' }}
          centered
        />
        <Modal.Title className="w-100 text-center text-secondary-emphasis">Ars0n Framework v2</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Row>
          {['Company', 'Wildcard', 'URL'].map((type) => (
            <Col key={type}>
              <Card
                className={`mb-3 h-200 text-center ${selections.type === type ? 'border-danger' : ''}`}
                onClick={() => handleSelect('type', type)}
                style={{ cursor: 'pointer' }}
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
                onClick={() => handleSelect('mode', mode)}
                style={{ cursor: 'pointer' }}
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
          placeholder="Google, *.google.com, https://hackme.google.com"
          value={selections.inputText}
          onChange={(e) => handleSelect('inputText', e.target.value)}
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