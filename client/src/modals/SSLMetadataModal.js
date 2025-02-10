import React from 'react';
import { Modal, Badge, Accordion, Card } from 'react-bootstrap';

const SSLMetadataModal = ({
  showSSLMetadataModal,
  handleCloseSSLMetadataModal,
  targetURLs
}) => {
  const getSeverityBadgeColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'danger';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'secondary';
    }
  };

  return (
    <Modal
      data-bs-theme="dark"
      show={showSSLMetadataModal}
      onHide={handleCloseSSLMetadataModal}
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Metadata Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-4">
            {targetURLs.map((url) => {
              const sslIssues = [];
              if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
              if (url.has_expired_ssl) sslIssues.push('Expired SSL');
              if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
              if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
              if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
              if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');

              return (
              <Accordion key={url.id} className="mb-3">
                <Accordion.Item eventKey="0">
                  <Accordion.Header>
                    <div className="d-flex justify-content-between align-items-center w-100 me-3">
                      <div className="d-flex align-items-center">
                        <span>{url.url}</span>
                        {url.findings_json && url.findings_json.length > 0 && (
                          <Badge 
                            bg="info" 
                            className="ms-2"
                            style={{ fontSize: '0.8em' }}
                          >
                            {url.findings_json.length} Technologies
                          </Badge>
                        )}
                      </div>
                      <div>
                    {sslIssues.length > 0 ? (
                      sslIssues.map((issue, index) => (
                        <Badge 
                          key={index} 
                          bg="danger" 
                          className="me-1"
                          style={{ fontSize: '0.8em' }}
                        >
                          {issue}
                        </Badge>
                      ))
                    ) : (
                          <Badge 
                            bg="success" 
                            className="me-1"
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
                        <p className="mb-1"><strong>Status Code:</strong> {url.status_code}</p>
                        <p className="mb-1"><strong>Title:</strong> {url.title || 'N/A'}</p>
                        <p className="mb-1"><strong>Web Server:</strong> {url.web_server || 'N/A'}</p>
                        <p className="mb-1"><strong>Content Length:</strong> {url.content_length}</p>
                      </div>
                    </div>
                    {url.findings_json && url.findings_json.length > 0 && (
                      <div>
                        <h6 className="text-danger mb-3">Technology Stack</h6>
                        <div className="ms-3">
                          {url.findings_json.map((finding, index) => (
                            <Card key={index} className="mb-3 bg-dark border-secondary">
                              <Card.Header className="d-flex justify-content-between align-items-center">
                                <div>
                                  <span className="text-white">
                                    <strong>{finding.info?.name || finding.template}</strong>
                                  </span>
                                </div>
                                <Badge 
                                  bg={getSeverityBadgeColor(finding.info?.severity)}
                                  style={{ fontSize: '0.8em' }}
                                >
                                  {finding.info?.severity || 'Info'}
                                </Badge>
                              </Card.Header>
                              <Card.Body>
                                <div className="mb-3">
                                  <p className="mb-2 text-white-50">
                                    {finding.info?.description || 'No description available'}
                                  </p>
                                  {finding['matcher-name'] && (
                                    <div className="mb-2">
                                      <strong>Technology:</strong> <span className="text-white-50">{finding['matcher-name'].toUpperCase()}</span>
                                      {finding.type && (
                                        <Badge 
                                          bg="info" 
                                          className="ms-2"
                                          style={{ fontSize: '0.8em' }}
                                        >
                                          {finding.type}
                                        </Badge>
                                      )}
                                    </div>
                                  )}
                                  {finding.info?.classification && Object.values(finding.info.classification).some(value => value) && (
                                    <div className="mb-2">
                                      <strong>Classification:</strong>
                                      <ul className="mb-0">
                                        {Object.entries(finding.info.classification).map(([key, value]) => (
                                          value && <li key={key}>{key}: {value}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                  {finding.info?.reference && finding.info.reference.length > 0 && (
                                    <div className="mb-2">
                                      <strong>References:</strong>
                                      <ul className="mb-0">
                                        {finding.info.reference.map((ref, i) => (
                                          <li key={i}>
                                            <a 
                                              href={ref} 
                                              target="_blank" 
                                              rel="noopener noreferrer"
                                              className="text-info"
                                            >
                                              {ref}
                                            </a>
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                </div>
                              </Card.Body>
                            </Card>
                          ))}
                        </div>
                      </div>
                    )}
                  </Accordion.Body>
                </Accordion.Item>
              </Accordion>
              );
            })}
        </div>
      </Modal.Body>
    </Modal>
  );
};

export default SSLMetadataModal; 