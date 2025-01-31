import { useState, useEffect } from 'react';
import { Modal, Table, Tab, Nav } from 'react-bootstrap';

export const DNSRecordsModal = ({ showDNSRecordsModal, handleCloseDNSRecordsModal, dnsRecords }) => {
  const records = Array.isArray(dnsRecords) ? dnsRecords : [];
  
  return (
    <Modal data-bs-theme="dark" show={showDNSRecordsModal} onHide={handleCloseDNSRecordsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">DNS Records</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover>
          <thead>
            <tr>
              <th>Record</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            {records.map((record, index) => (
              <tr key={index}>
                <td>{record.record}</td>
                <td>{record.type}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
};

export const SubdomainsModal = ({ showSubdomainsModal, handleCloseSubdomainsModal, subdomains }) => {
  const subs = Array.isArray(subdomains) ? subdomains : [];
  
  return (
    <Modal data-bs-theme="dark" show={showSubdomainsModal} onHide={handleCloseSubdomainsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Subdomains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover>
          <thead>
            <tr>
              <th>Subdomain</th>
            </tr>
          </thead>
          <tbody>
            {subs.map((subdomain, index) => (
              <tr key={index}>
                <td>{subdomain}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
};

export const CloudDomainsModal = ({ showCloudDomainsModal, handleCloseCloudDomainsModal, cloudDomains }) => {
  const domains = Array.isArray(cloudDomains) ? cloudDomains : [];
  
  return (
    <Modal data-bs-theme="dark" show={showCloudDomainsModal} onHide={handleCloseCloudDomainsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Cloud Domains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover>
          <thead>
            <tr>
              <th>Provider</th>
              <th>Domain</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((domain, index) => (
              <tr key={index}>
                <td>{domain.type}</td>
                <td>{domain.name}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
};

export const InfrastructureMapModal = ({ showInfraModal, handleCloseInfraModal, scanId }) => {
  const [asns, setAsns] = useState([]);
  const [subnets, setSubnets] = useState([]);
  const [serviceProviders, setServiceProviders] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      if (scanId && scanId !== 'No scans available') {
        try {
          const [asnResponse, subnetResponse, spResponse] = await Promise.all([
            fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/asn`),
            fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/subnet`),
            fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/sp`)
          ]);

          const [asnData, subnetData, spData] = await Promise.all([
            asnResponse.json(),
            subnetResponse.json(),
            spResponse.json()
          ]);

          setAsns(Array.isArray(asnData) ? asnData : []);
          setSubnets(Array.isArray(subnetData) ? subnetData : []);
          setServiceProviders(Array.isArray(spData) ? spData : []);
        } catch (error) {
          console.error('Error fetching infrastructure data:', error);
          setAsns([]);
          setSubnets([]);
          setServiceProviders([]);
        }
      } else {
        setAsns([]);
        setSubnets([]);
        setServiceProviders([]);
      }
    };

    fetchData();
  }, [scanId]);

  return (
    <Modal data-bs-theme="dark" show={showInfraModal} onHide={handleCloseInfraModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Infrastructure Map</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tab.Container defaultActiveKey="asns">
          <Nav variant="tabs" className="mb-3">
            <Nav.Item>
              <Nav.Link eventKey="asns">ASNs ({asns.length})</Nav.Link>
            </Nav.Item>
            <Nav.Item>
              <Nav.Link eventKey="subnets">Subnets ({subnets.length})</Nav.Link>
            </Nav.Item>
            <Nav.Item>
              <Nav.Link eventKey="providers">Service Providers ({serviceProviders.length})</Nav.Link>
            </Nav.Item>
          </Nav>

          <Tab.Content>
            <Tab.Pane eventKey="asns">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>ASN</th>
                    <th>Raw Data</th>
                  </tr>
                </thead>
                <tbody>
                  {asns.map((asn, index) => (
                    <tr key={index}>
                      <td>{asn.number}</td>
                      <td>{asn.raw_data}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>

            <Tab.Pane eventKey="subnets">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>CIDR</th>
                    <th>Raw Data</th>
                  </tr>
                </thead>
                <tbody>
                  {subnets.map((subnet, index) => (
                    <tr key={index}>
                      <td>{subnet.cidr}</td>
                      <td>{subnet.raw_data}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>

            <Tab.Pane eventKey="providers">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Raw Data</th>
                  </tr>
                </thead>
                <tbody>
                  {serviceProviders.map((provider, index) => (
                    <tr key={index}>
                      <td>{provider.provider}</td>
                      <td>{provider.raw_data}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>
          </Tab.Content>
        </Tab.Container>
      </Modal.Body>
    </Modal>
  );
};
