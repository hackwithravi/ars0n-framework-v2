import { useState } from 'react';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';

function App() {
  const [showModal, setShowModal] = useState(true);
  const [selections, setSelections] = useState({
    type: '',
    mode: '',
    inputText: '',
  });

  const handleClose = () => setShowModal(false);

  const handleSelect = (key, value) => {
    setSelections((prev) => ({ ...prev, [key]: value }));
  };

  const handleSubmit = () => {
    if (selections.type && selections.mode && selections.inputText) {
      setShowModal(false);
    } else {
      alert('Please complete all fields.');
    }
  };

  return (
    <div className="App" style={{ padding: '20px' }} data-bs-theme="dark">
      <AddScopeTargetModal
        show={showModal}
        handleClose={handleClose}
        selections={selections}
        handleSelect={handleSelect}
        handleSubmit={handleSubmit}
      />

      {!showModal && (
        <div data-bs-theme="dark">
          <h3>Your Selections</h3>
          <p>
            <strong>Type:</strong> {selections.type}
          </p>
          <p>
            <strong>Mode:</strong> {selections.mode}
          </p>
          <p>
            <strong>Input:</strong> {selections.inputText}
          </p>
        </div>
      )}
    </div>
  );
}

export default App;
