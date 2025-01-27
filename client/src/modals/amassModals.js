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

const InfrastructureMapModal = ({ showInfraModal, handleCloseInfraModal, scanId }) => {
  const [infraData, setInfraData] = useState({
    asns: [],
    serviceProviders: [],
    subnets: [],
    dnsRecords: []
  });

  useEffect(() => {
    if (scanId) {
      Promise.all([
        fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/asn`),
        fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/sp`),
        fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/subnet`),
        fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/${scanId}/dns`)
      ])
        .then(async ([asnRes, spRes, subnetRes, dnsRes]) => {
          const [asns, serviceProviders, subnets, dnsRecords] = await Promise.all([
            asnRes.json(),
            spRes.json(),
            subnetRes.json(),
            dnsRes.json()
          ]);

          // Remove duplicate ASNs based on ASN number
          const uniqueAsns = [...new Map(asns.map(item => {
            const asnNumber = item.raw_data.match(/^\d+/)[0];
            return [asnNumber, item];
          })).values()];

          setInfraData({ 
            asns: uniqueAsns, 
            serviceProviders, 
            subnets, 
            dnsRecords 
          });
        })
        .catch(error => console.error('Error fetching infrastructure data:', error));
    }
  }, [scanId]);

  const getSubnetsForAsn = (asn) => {
    const asnNumber = asn.raw_data.match(/^\d+/)[0];
    return infraData.subnets.filter(subnet => 
      subnet.raw_data.includes(`${asnNumber} (ASN) --> announces`)
    );
  };

  const getDnsRecordsForSubnet = (subnet) => {
    const subnetCidr = subnet.raw_data.match(/([0-9a-f:./]+)\s+\(Netblock\)/i)[1];
    return infraData.dnsRecords.filter(record => {
      const ipMatch = record.record.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      if (!ipMatch) return false;
      
      const ip = ipMatch[0];
      const [subnetBase, mask] = subnetCidr.split('/');
      
      // Simple IP matching - could be enhanced with proper subnet calculation
      return ip.startsWith(subnetBase.split('.').slice(0, mask >= 24 ? 3 : 2).join('.'));
    });
  };

  const getUnassociatedDnsRecords = () => {
    const allSubnets = infraData.subnets.map(subnet => {
      const match = subnet.raw_data.match(/([0-9a-f:./]+)\s+\(Netblock\)/i);
      return match ? match[1] : null;
    }).filter(Boolean);

    return infraData.dnsRecords.filter(record => {
      const ipMatch = record.record.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      if (!ipMatch) return true; // Include records without IPs
      
      const ip = ipMatch[0];
      return !allSubnets.some(subnetCidr => {
        const [subnetBase, mask] = subnetCidr.split('/');
        return ip.startsWith(subnetBase.split('.').slice(0, mask >= 24 ? 3 : 2).join('.'));
      });
    });
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={showInfraModal} 
      onHide={handleCloseInfraModal} 
      size="xl" 
      fullscreen={true}
    >
      <Modal.Header closeButton>
        <Modal.Title style={{ color: '#FF4500' }}>Infrastructure Map</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ backgroundColor: '#1a1a1a' }}>
        <div style={{ padding: '20px', overflowY: 'auto', height: 'calc(100vh - 120px)', fontFamily: 'monospace' }}>
          {infraData.asns.map((asn, i) => (
            <div key={i} className="mb-4">
              <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                <li>
                  <span style={{ color: '#FF4500' }}>{asn.raw_data}</span>
                  <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                    {getSubnetsForAsn(asn).map((subnet, j) => (
                      <li key={j} style={{ paddingLeft: "100px", color: '#FFD700' }}>
                        {subnet.raw_data}
                        <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                          {getDnsRecordsForSubnet(subnet).map((record, k) => (
                            <li key={k} style={{ paddingLeft: "100px", color: '#FF8C00' }}>
                              {record.record}
                              {record.record.split(" ")[0] && (
                                <span style={{ marginLeft: '10px', color: '#FF6B6B' }}>
                                  --- LINK: <a 
                                    href={`https://${record.record.split(" ")[0]}`} 
                                    target="_blank" 
                                    rel="noreferrer"
                                    style={{ color: '#FFA07A', textDecoration: 'none' }}
                                  >
                                    {`https://${record.record.split(" ")[0]}`}
                                  </a>
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </li>
                    ))}
                  </ul>
                </li>
              </ul>
            </div>
          ))}
          {getUnassociatedDnsRecords().length > 0 && (
            <div className="mb-4">
              <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                <li>
                  <span style={{ color: '#FF4500' }}>Unknown ASN</span>
                  <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                    <li style={{ paddingLeft: "100px", color: '#FFD700' }}>
                      Unknown Subnet
                      <ul style={{ listStyleType: "none", padding: "0", margin: "0" }}>
                        {getUnassociatedDnsRecords().map((record, k) => (
                          <li key={k} style={{ paddingLeft: "100px", color: '#FF8C00' }}>
                            {record.record}
                            {record.record.split(" ")[0] && (
                              <span style={{ marginLeft: '10px', color: '#FF6B6B' }}>
                                --- LINK: <a 
                                  href={`https://${record.record.split(" ")[0]}`} 
                                  target="_blank" 
                                  rel="noreferrer"
                                  style={{ color: '#FFA07A', textDecoration: 'none' }}
                                >
                                  {`https://${record.record.split(" ")[0]}`}
                                </a>
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </li>
                  </ul>
                </li>
              </ul>
            </div>
          )}
        </div>
      </Modal.Body>
    </Modal>
  );
};

export { DNSRecordsModal, SubdomainsModal, CloudDomainsModal, InfrastructureMapModal };
