import { Modal, Badge, Accordion } from 'react-bootstrap';
import { useEffect } from 'react';

const MetaDataModal = ({
  showMetaDataModal,
  handleCloseMetaDataModal,
  targetURLs = [],
  setTargetURLs
}) => {

  useEffect(() => {
    const handleMetadataScanComplete = (event) => {
      setTargetURLs(event.detail);
    };

    window.addEventListener('metadataScanComplete', handleMetadataScanComplete);

    return () => {
      window.removeEventListener('metadataScanComplete', handleMetadataScanComplete);
    };
  }, [setTargetURLs]);

  const getStatusCodeColor = (statusCode) => {
    if (!statusCode) return { bg: 'secondary', text: 'white' };
    if (statusCode >= 200 && statusCode < 300) return { bg: 'success', text: 'dark' };
    if (statusCode >= 300 && statusCode < 400) return { bg: 'info', text: 'dark' };
    if (statusCode === 401 || statusCode === 403) return { bg: 'danger', text: 'white' };
    if (statusCode >= 400 && statusCode < 500) return { bg: 'warning', text: 'dark' };
    if (statusCode >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'secondary', text: 'white' };
  };

  const urls = Array.isArray(targetURLs) ? targetURLs : [];

  const getSafeValue = (value) => {
    if (!value) return '';
    if (typeof value === 'object' && 'String' in value) {
      return value.String || '';
    }
    return value;
  };

  return (
    <Modal
      data-bs-theme="dark"
      show={showMetaDataModal}
      onHide={handleCloseMetaDataModal}
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Metadata Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-4">
            {urls.length === 0 ? (
              <div className="text-center text-muted">
                No metadata results available
              </div>
            ) : (
              urls.map((url) => {
                const sslIssues = [];
                if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
                if (url.has_expired_ssl) sslIssues.push('Expired SSL');
                if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
                if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
                if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
                if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');

                const findings = Array.isArray(url.findings_json) ? url.findings_json : [];

                return (
                <Accordion key={url.id} className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header>
                      <div className="d-flex justify-content-between align-items-center w-100 me-3">
                        <div className="d-flex align-items-center">
                          <Badge 
                            bg={getStatusCodeColor(url.status_code).bg}
                            className={`me-2 text-${getStatusCodeColor(url.status_code).text}`}
                            style={{ fontSize: '0.8em' }}
                          >
                            {url.status_code}
                          </Badge>
                          <span>{url.url}</span>
                        </div>
                        <div className="d-flex align-items-center gap-2">
                          {findings.length > 0 && (
                            <Badge 
                              bg="secondary" 
                              style={{ fontSize: '0.8em' }}
                            >
                              {findings.length} Technologies
                            </Badge>
                          )}
                          {sslIssues.length > 0 ? (
                            sslIssues.map((issue, index) => (
                              <Badge 
                                key={index} 
                                bg="danger" 
                                style={{ fontSize: '0.8em' }}
                              >
                                {issue}
                              </Badge>
                            ))
                          ) : (
                            <Badge 
                              bg="success" 
                              style={{ fontSize: '0.8em' }}
                            >
                              No SSL Issues
                            </Badge>
                          )}
                        </div>
                      </div>
                    </Accordion.Header>
                    <Accordion.Body>
                      <div className="mb-4">
                        <h6 className="text-danger mb-3">Server Information</h6>
                        <div className="ms-3">
                          <p className="mb-1"><strong>Title:</strong> {getSafeValue(url.title) || 'N/A'}</p>
                          <p className="mb-1"><strong>Web Server:</strong> {getSafeValue(url.web_server) || 'N/A'}</p>
                          <p className="mb-1"><strong>Content Length:</strong> {url.content_length}</p>
                          {url.technologies && url.technologies.length > 0 && (
                            <p className="mb-1">
                              <strong>Technologies:</strong>{' '}
                              {url.technologies.map((tech, index) => (
                                <Badge 
                                  key={index} 
                                  bg="secondary" 
                                  className="me-1"
                                  style={{ fontSize: '0.8em' }}
                                >
                                  {tech}
                                </Badge>
                              ))}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="mb-4">
                        <h6 className="text-danger mb-3">DNS Information</h6>
                        <div className="ms-3">
                          <Accordion>
                            {[
                              { 
                                title: 'A Records', 
                                records: url.dns_a_records || [],
                                description: 'Maps hostnames to IPv4 addresses'
                              },
                              { 
                                title: 'AAAA Records', 
                                records: url.dns_aaaa_records || [],
                                description: 'Maps hostnames to IPv6 addresses'
                              },
                              { 
                                title: 'CNAME Records', 
                                records: url.dns_cname_records || [],
                                description: 'Canonical name records - Maps one domain name (alias) to another (canonical name)'
                              },
                              { 
                                title: 'MX Records', 
                                records: url.dns_mx_records || [],
                                description: 'Mail exchange records - Specifies mail servers responsible for receiving email'
                              },
                              { 
                                title: 'TXT Records', 
                                records: url.dns_txt_records || [],
                                description: 'Text records - Holds human/machine-readable text data, often used for domain verification'
                              },
                              { 
                                title: 'NS Records', 
                                records: url.dns_ns_records || [],
                                description: 'Nameserver records - Delegates a DNS zone to authoritative nameservers'
                              },
                              { 
                                title: 'PTR Records', 
                                records: url.dns_ptr_records || [],
                                description: 'Pointer records - Maps IP addresses to hostnames (reverse DNS)'
                              },
                              { 
                                title: 'SRV Records', 
                                records: url.dns_srv_records || [],
                                description: 'Service records - Specifies location of servers for specific services'
                              }
                            ].map((recordType, index) => {
                              return (recordType.records && recordType.records.length > 0 && (
                                <Accordion.Item key={index} eventKey={index.toString()}>
                                  <Accordion.Header>
                                    <div>
                                      <span className="text-white">
                                        {recordType.title} ({recordType.records.length})
                                      </span>
                                      <br/>
                                      <small className="text-muted">{recordType.description}</small>
                                    </div>
                                  </Accordion.Header>
                                  <Accordion.Body>
                                    <div className="bg-dark p-3 rounded font-monospace" style={{ fontSize: '0.85em' }}>
                                      {recordType.records.map((record, recordIndex) => {
                                        let displayRecord = record;
                                        if (recordType.title === 'MX Records') {
                                          const [host, priority] = record.split(' ');
                                          displayRecord = `Priority: ${priority} | Mail Server: ${host}`;
                                        } else if (recordType.title === 'SRV Records') {
                                          const [service, port, priority, weight] = record.split(' ');
                                          displayRecord = `Service: ${service} | Port: ${port} | Priority: ${priority} | Weight: ${weight}`;
                                        } else if (recordType.title === 'CNAME Records') {
                                          displayRecord = record;
                                        }
                                        return (
                                          <div key={recordIndex} className="mb-1">
                                            {displayRecord}
                                          </div>
                                        );
                                      })}
                                    </div>
                                  </Accordion.Body>
                                </Accordion.Item>
                              ))
                            })}
                          </Accordion>
                        </div>
                      </div>
                      {(getSafeValue(url.http_response) || url.http_response_headers) && (
                        <div className="mb-4">
                          <h6 className="text-danger mb-3">HTTP Response Data</h6>
                          <div className="ms-3">
                            {url.http_response_headers && (
                              <div className="mb-3">
                                <Accordion>
                                  <Accordion.Item eventKey="0">
                                    <Accordion.Header>
                                      <span className="text-white">Response Headers</span>
                                    </Accordion.Header>
                                    <Accordion.Body>
                                      <div className="bg-dark p-3 rounded" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                                        {Object.entries(url.http_response_headers).map(([key, value]) => (
                                          <p key={key} className="mb-1 font-monospace">
                                            <strong>{key}:</strong> {Array.isArray(value) ? value.join(', ') : value}
                                          </p>
                                        ))}
                                      </div>
                                    </Accordion.Body>
                                  </Accordion.Item>
                                </Accordion>
                              </div>
                            )}
                            {getSafeValue(url.http_response) && (
                              <div>
                                <Accordion>
                                  <Accordion.Item eventKey="0">
                                    <Accordion.Header>
                                      <span className="text-white">Response Body</span>
                                    </Accordion.Header>
                                    <Accordion.Body>
                                      <div 
                                        className="bg-dark p-3 rounded font-monospace" 
                                        style={{ 
                                          maxHeight: '400px', 
                                          overflowY: 'auto',
                                          whiteSpace: 'pre-wrap',
                                          wordBreak: 'break-word',
                                          fontSize: '0.85em'
                                        }}
                                      >
                                        {getSafeValue(url.http_response)}
                                      </div>
                                    </Accordion.Body>
                                  </Accordion.Item>
                                </Accordion>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                      {findings.length > 0 && (
                        <div>
                          <h6 className="text-danger mb-3">Technology Stack</h6>
                          <div className="ms-3">
                            {findings.map((finding, index) => (
                              <div key={index} className="mb-2 text-white">
                                {(finding.info?.name || finding.template)} -- {finding['matcher-name']?.toUpperCase()}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                );
              })
            )}
        </div>
      </Modal.Body>
    </Modal>
  );
};

export default MetaDataModal; 