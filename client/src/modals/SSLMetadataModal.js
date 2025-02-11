import React from 'react';
import { Modal, Badge, Accordion } from 'react-bootstrap';

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

  const getStatusCodeColor = (statusCode) => {
    if (!statusCode) return { bg: 'secondary', text: 'white' };
    if (statusCode >= 200 && statusCode < 300) return { bg: 'success', text: 'dark' };
    if (statusCode >= 300 && statusCode < 400) return { bg: 'info', text: 'dark' };
    if (statusCode === 401 || statusCode === 403) return { bg: 'danger', text: 'white' };
    if (statusCode >= 400 && statusCode < 500) return { bg: 'warning', text: 'dark' };
    if (statusCode >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'secondary', text: 'white' };
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
                        {url.findings_json && url.findings_json.length > 0 && (
                          <Badge 
                            bg="secondary" 
                            style={{ fontSize: '0.8em' }}
                          >
                            {url.findings_json.length} Technologies
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
                        <p className="mb-1"><strong>Title:</strong> {url.title || 'N/A'}</p>
                        <p className="mb-1"><strong>Web Server:</strong> {url.web_server || 'N/A'}</p>
                        <p className="mb-1"><strong>Content Length:</strong> {url.content_length}</p>
                      </div>
                    </div>
                    {(url.http_response || url.http_response_headers) && (
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
                          {url.http_response && (
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
                                      {url.http_response}
                                    </div>
                                  </Accordion.Body>
                                </Accordion.Item>
                              </Accordion>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    {url.findings_json && url.findings_json.length > 0 && (
                      <div>
                        <h6 className="text-danger mb-3">Technology Stack</h6>
                        <div className="ms-3">
                          {url.findings_json.map((finding, index) => (
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
            })}
        </div>
      </Modal.Body>
    </Modal>
  );
};

export default SSLMetadataModal; 