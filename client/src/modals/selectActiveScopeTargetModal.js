import { Modal, ListGroup, Button } from 'react-bootstrap';

function SelectActiveScopeTargetModal({
  showActiveModal,
  handleActiveModalClose,
  scopeTargets,
  activeTarget,
  handleActiveSelect,
  handleDelete,
}) {
  return (
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
  );
}

export default SelectActiveScopeTargetModal;
