import { useState, useEffect } from 'react';
import AddScopeTargetModal from './modals/addScopeTargetModal.js';

function App() {
  const [showModal, setShowModal] = useState(false);
  const [selections, setSelections] = useState({
    type: '',
    mode: '',
    inputText: '',
  });
  const [scopeTargets, setScopeTargets] = useState([]);
  const [errorMessage, setErrorMessage] = useState('');

  const handleClose = () => {
    setShowModal(false);
    setErrorMessage('');
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

  const handleDelete = async (id) => {
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/delete/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error('Failed to delete scope target');
      }
      setScopeTargets((prev) => {
        const updatedTargets = prev.filter((target) => target.id !== id);
        if (updatedTargets.length === 0) {
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
      if (!data || data.length === 0) {
        setShowModal(true);
      }
    } catch (error) {
      console.error('Error fetching scope targets:', error);
      setScopeTargets([]);
    }
  };

  useEffect(() => {
    fetchScopeTargets();
  }, []);

  return (
    <div className="App" style={{ padding: '20px' }}>
      <AddScopeTargetModal
        show={showModal}
        handleClose={handleClose}
        selections={selections}
        handleSelect={handleSelect}
        handleFormSubmit={handleSubmit}
        errorMessage={errorMessage}
      />

      {!showModal && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3>Scope Targets</h3>
            <button
              onClick={handleOpen}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '45px',
                cursor: 'pointer',
                padding: '5px',
                color: '#8B0000',
              }}
              onMouseEnter={(e) => (e.target.style.color = '#FF0000')}
              onMouseLeave={(e) => (e.target.style.color = '#8B0000')}
              aria-label="Add Scope Target"
            >
              +
            </button>
          </div>

          <ul>
            {Array.isArray(scopeTargets) && scopeTargets.map((target) => (
              <li key={target.id} style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ flexGrow: 1 }}>
                  <strong>{target.scope_target}</strong> - {target.type} ({target.mode})
                </span>
                <button
                  onClick={() => handleDelete(target.id)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  🗑️
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
