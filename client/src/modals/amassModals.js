import { useState, useEffect } from 'react';
import { Modal, Form, ListGroup, Button } from 'react-bootstrap';

const DNSRecordsModal = ({ showDNSRecordsModal, handleCloseDNSRecordsModal, dnsRecords }) => {
  const [filterOptions, setFilterOptions] = useState({});
  const [filteredRecords, setFilteredRecords] = useState([]);

  useEffect(() => {
    try {
      const initialFilterOptions = dnsRecords.reduce((acc, record) => {
        acc[record.type] = true;
        return acc;
      }, {});
      setFilterOptions(initialFilterOptions);
      setFilteredRecords(dnsRecords);
    } catch {
      setFilterOptions({});
      setFilteredRecords([]);
    }
  }, [dnsRecords]);

  const handleFilterChange = (recordType) => {
    const updatedFilterOptions = {
      ...filterOptions,
      [recordType]: !filterOptions[recordType],
    };

    setFilterOptions(updatedFilterOptions);

    const updatedFilteredRecords = dnsRecords.filter(
      (record) => updatedFilterOptions[record.type]
    );
    setFilteredRecords(updatedFilteredRecords);
  };

  return (
    <Modal data-bs-theme="dark" show={showDNSRecordsModal} onHide={handleCloseDNSRecordsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">DNS Records</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-3 d-flex justify-content-center">
          <Button
            variant="outline-danger"
            className="w-75"
            onClick={() => alert('Testing for subdomain takeover')}
          >
            Test For Subdomain Takeover
          </Button>
        </div>
        <Form className="d-flex justify-content-between flex-wrap">
          {Array.isArray(dnsRecords) && dnsRecords.length > 0 ? (
            Array.from(new Set(dnsRecords.map((record) => record.type))).map((recordType) => (
              <Form.Check
                className="text-danger custom-checkbox"
                key={recordType}
                type="checkbox"
                label={recordType}
                checked={filterOptions[recordType] || false}
                onChange={() => handleFilterChange(recordType)}
              />
            ))
          ) : (
            <p>No DNS records available</p>
          )}
        </Form>
        <ListGroup className="mt-3">
          {filteredRecords.map((record) => (
            <ListGroup.Item key={record.id}>{record.record}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

const SubdomainsModal = ({ showSubdomainsModal, handleCloseSubdomainsModal, subdomains }) => {
  return (
    <Modal data-bs-theme="dark" show={showSubdomainsModal} onHide={handleCloseSubdomainsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Subdomains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <ListGroup className="mt-3">
          {subdomains.map((subdomain, index) => (
            <ListGroup.Item key={index}>{subdomain}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

const CloudDomainsModal = ({ showCloudDomainsModal, handleCloseCloudDomainsModal, cloudDomains }) => {
  const [filterOptions, setFilterOptions] = useState({});
  const [filteredDomains, setFilteredDomains] = useState(cloudDomains);

  useEffect(() => {
    const initialFilterOptions = cloudDomains.reduce((acc, domain) => {
      acc[domain.type] = true;
      return acc;
    }, {});
    setFilterOptions(initialFilterOptions);
    setFilteredDomains(cloudDomains);
  }, [cloudDomains]);

  const handleFilterChange = (cloudType) => {
    const updatedFilterOptions = {
      ...filterOptions,
      [cloudType]: !filterOptions[cloudType],
    };

    setFilterOptions(updatedFilterOptions);

    const updatedFilteredDomains = cloudDomains.filter(
      (domain) => updatedFilterOptions[domain.type]
    );
    setFilteredDomains(updatedFilteredDomains);
  };

  return (
    <Modal data-bs-theme="dark" show={showCloudDomainsModal} onHide={handleCloseCloudDomainsModal} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Cloud Domains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form className="d-flex flex-wrap gap-5 justify-content-center px-3">
          {Array.from(new Set(cloudDomains.map((domain) => domain.type))).map((cloudType) => (
            <Form.Check
              className="text-primary custom-checkbox"
              key={cloudType}
              type="checkbox"
              label={cloudType}
              checked={filterOptions[cloudType] || false}
              onChange={() => handleFilterChange(cloudType)}
            />
          ))}
        </Form>

        <ListGroup className="mt-3">
          {filteredDomains.map((domain, index) => (
            <ListGroup.Item key={index}>{domain.name}</ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
    </Modal>
  );
};

export { DNSRecordsModal, SubdomainsModal, CloudDomainsModal };
