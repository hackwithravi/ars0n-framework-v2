import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col, Spinner, Accordion } from 'react-bootstrap';

function SettingsModal({ show, handleClose }) {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    if (show) {
      fetchSettings();
      setSaveSuccess(false);
    }
  }, [show]);

  const fetchSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/user/settings`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch settings');
      }
      
      const data = await response.json();
      
      // Default settings
      const defaultSettings = {
        amass_rate_limit: 10,
        httpx_rate_limit: 150,
        subfinder_rate_limit: 20,
        gau_rate_limit: 10,
        sublist3r_rate_limit: 10,
        ctl_rate_limit: 10,
        shuffledns_rate_limit: 10000,
        cewl_rate_limit: 10,
        gospider_rate_limit: 5,
        subdomainizer_rate_limit: 5,
        nuclei_screenshot_rate_limit: 20
      };
      
      // Check if data is empty or missing expected properties
      const hasSettings = data && Object.keys(data).length > 0;
      
      // Use data if it has settings, otherwise use defaults
      setSettings(hasSettings ? data : defaultSettings);
    } catch (error) {
      console.error('Error fetching settings:', error);
      setError('Failed to load settings. Please try again.');
      // Set default values if fetch fails
      setSettings({
        amass_rate_limit: 10,
        httpx_rate_limit: 150,
        subfinder_rate_limit: 20,
        gau_rate_limit: 10,
        sublist3r_rate_limit: 10,
        ctl_rate_limit: 10,
        shuffledns_rate_limit: 10000,
        cewl_rate_limit: 10,
        gospider_rate_limit: 5,
        subdomainizer_rate_limit: 5,
        nuclei_screenshot_rate_limit: 20
      });
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (tool, value) => {
    setSaveSuccess(false);
    setSettings(prev => ({
      ...prev,
      [`${tool}_rate_limit`]: parseInt(value)
    }));
  };

  const handleSave = async () => {
    try {
      setLoading(true);
      setSaveSuccess(false);
      setError(null);
      
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/user/settings`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(settings),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save settings');
      }

      setSaveSuccess(true);
      setTimeout(() => {
        handleClose();
      }, 1500);
    } catch (error) {
      console.error('Error saving settings:', error);
      setError('Failed to save settings. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const renderSlider = (tool, label, min, max, step, description) => (
    <Form.Group as={Row} className="mb-4 align-items-center">
      <Form.Label column sm={4} className="text-white">
        {label} Rate Limit
      </Form.Label>
      <Col sm={6}>
        <Form.Range
          min={min}
          max={max}
          step={step}
          value={settings[`${tool}_rate_limit`] || min}
          onChange={(e) => handleChange(tool, e.target.value)}
        />
        <p className="text-white-50 small mt-1">{description}</p>
      </Col>
      <Col sm={2} className="text-white text-center">
        {settings[`${tool}_rate_limit`] || min}
      </Col>
    </Form.Group>
  );

  // Tool descriptions
  const toolDescriptions = {
    amass: "Controls requests per second for DNS queries. Higher values may trigger rate limiting by DNS servers.",
    httpx: "Limits concurrent HTTP requests. Higher values increase speed but may trigger WAF blocks or IP bans.",
    subfinder: "Controls API request rate for passive sources. Higher values may exceed API rate limits.",
    gau: "Limits requests to archive.org and other sources. Higher values may trigger temporary IP blocks.",
    sublist3r: "Controls API request rate for multiple sources. Higher values may exceed API rate limits.",
    ctl: "Controls requests to Certificate Transparency logs. IMPORTANT: Values above 10 may result in temporary IP blocks from CT log providers.",
    shuffledns: "Controls concurrent massdns resolves. Default is 10000 as per shuffledns documentation.",
    cewl: "Limits requests when crawling web pages for words. Higher values may trigger WAF blocks.",
    gospider: "Controls concurrent crawling threads. Higher values may trigger anti-bot measures.",
    subdomainizer: "Limits requests when analyzing JavaScript files. Higher values may trigger rate limiting.",
    nuclei_screenshot: "Controls concurrent screenshot requests. Higher values increase speed but may trigger anti-bot measures."
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Settings</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-4">
            <Spinner animation="border" variant="danger" />
            <p className="text-white mt-3">Loading settings...</p>
          </div>
        ) : error ? (
          <div className="alert alert-danger">{error}</div>
        ) : saveSuccess ? (
          <div className="alert alert-success">Settings saved successfully!</div>
        ) : (
          <Form>
            <h5 className="text-danger mb-3">Tool Rate Limits</h5>
            <p className="text-white-50 small mb-4">
              Adjust the rate limits for each tool to balance between speed and avoiding rate limiting by target servers.
              Higher values = faster scans, but may trigger rate limiting or IP blocks.
            </p>
            
            <Accordion className="mb-4">
              <Accordion.Item eventKey="0">
                <Accordion.Header>About Rate Limiting</Accordion.Header>
                <Accordion.Body>
                  <p className="text-white-50 small">
                    Rate limiting controls how aggressively each tool sends requests to target servers or APIs. 
                    Setting appropriate rate limits is crucial for:
                  </p>
                  <ul className="text-white-50 small">
                    <li><strong>Avoiding IP blocks:</strong> Many services will temporarily block your IP if you send too many requests too quickly</li>
                    <li><strong>Bypassing WAFs:</strong> Web Application Firewalls often trigger on high-volume scanning</li>
                    <li><strong>Respecting API limits:</strong> Many tools use APIs with strict rate limits</li>
                    <li><strong>Staying stealthy:</strong> Lower rate limits help avoid detection during security testing</li>
                  </ul>
                  <p className="text-white-50 small">
                    <strong>Note:</strong> The exact implementation of rate limiting varies by tool. Some use requests per second, 
                    others use concurrent connections, and some use a combination of both.
                  </p>
                </Accordion.Body>
              </Accordion.Item>
            </Accordion>
            
            {renderSlider('amass', 'Amass', 1, 50, 1, toolDescriptions.amass)}
            {renderSlider('httpx', 'HTTPX', 50, 500, 10, toolDescriptions.httpx)}
            {renderSlider('subfinder', 'Subfinder', 1, 100, 1, toolDescriptions.subfinder)}
            {renderSlider('gau', 'GAU', 1, 50, 1, toolDescriptions.gau)}
            {renderSlider('sublist3r', 'Sublist3r', 1, 50, 1, toolDescriptions.sublist3r)}
            {renderSlider('ctl', 'CTL', 1, 50, 1, toolDescriptions.ctl)}
            {renderSlider('shuffledns', 'ShuffleDNS', 1000, 20000, 1000, toolDescriptions.shuffledns)}
            {renderSlider('cewl', 'CeWL', 1, 50, 1, toolDescriptions.cewl)}
            {renderSlider('gospider', 'GoSpider', 1, 20, 1, toolDescriptions.gospider)}
            {renderSlider('subdomainizer', 'Subdomainizer', 1, 20, 1, toolDescriptions.subdomainizer)}
            {renderSlider('nuclei_screenshot', 'Nuclei Screenshot', 1, 100, 1, toolDescriptions.nuclei_screenshot)}
          </Form>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleSave} 
          disabled={loading || saveSuccess}
        >
          {loading ? 'Saving...' : saveSuccess ? 'Saved!' : 'Save Settings'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default SettingsModal; 