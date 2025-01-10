import { useState } from 'react';
import { Modal, Form, ListGroup, Button } from 'react-bootstrap';

const DNSRecordsModal = ({ showDNSRecordsModal, handleCloseDNSRecordsModal, dnsRecords }) => {
  const [filterOptions, setFilterOptions] = useState({});
  const [filteredRecords, setFilteredRecords] = useState(dnsRecords);

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
          {Array.from(new Set(dnsRecords.map((record) => record.type))).map((recordType) => (
            <Form.Check
              className="text-danger custom-checkbox"
              key={recordType}
              type="checkbox"
              label={recordType}
              checked={filterOptions[recordType] || false}
              onChange={() => handleFilterChange(recordType)}
            />
          ))}
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

export default DNSRecordsModal;
