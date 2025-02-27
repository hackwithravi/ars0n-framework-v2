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
      console.log('Metadata scan complete event received:', event.detail);
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
  console.log('Rendering MetaDataModal with URLs:', urls);

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
              urls.map((url, urlIndex) => {
                console.log(`Processing URL ${urlIndex}:`, url);
                console.log('ffuf_results for this URL:', url.ffuf_results);
                const sslIssues = [];
                if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
                if (url.has_expired_ssl) sslIssues.push('Expired SSL');
                if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
                if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
                if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
                if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');

                const findings = Array.isArray(url.findings_json) ? url.findings_json : [];
                const katanaUrls = Array.isArray(url.katana_results) ? url.katana_results : [];

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
                          <Badge 
                            bg="dark" 
                            className="text-white"
                            style={{ fontSize: '0.8em' }}
                          >
                            {katanaUrls.length} Crawled URLs
                          </Badge>
                          <Badge 
                            bg="dark" 
                            className="text-white"
                            style={{ fontSize: '0.8em' }}
                          >
                            {url.ffuf_results?.endpoints?.length || 0} Endpoints
                          </Badge>
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
                      {(() => {
                        const dnsRecordTypes = [
                          { 
                            title: 'A Records', 
                            records: url.dns_a_records || [],
                            description: 'Maps hostnames to IPv4 addresses',
                            badge: 'bg-primary'
                          },
                          { 
                            title: 'AAAA Records', 
                            records: url.dns_aaaa_records || [],
                            description: 'Maps hostnames to IPv6 addresses',
                            badge: 'bg-info'
                          },
                          { 
                            title: 'CNAME Records', 
                            records: url.dns_cname_records || [],
                            description: 'Canonical name records - Maps one domain name (alias) to another (canonical name)',
                            badge: 'bg-success'
                          },
                          { 
                            title: 'MX Records', 
                            records: url.dns_mx_records || [],
                            description: 'Mail exchange records - Specifies mail servers responsible for receiving email',
                            badge: 'bg-warning'
                          },
                          { 
                            title: 'TXT Records', 
                            records: url.dns_txt_records || [],
                            description: 'Text records - Holds human/machine-readable text data, often used for domain verification',
                            badge: 'bg-secondary'
                          },
                          { 
                            title: 'NS Records', 
                            records: url.dns_ns_records || [],
                            description: 'Nameserver records - Delegates a DNS zone to authoritative nameservers',
                            badge: 'bg-danger'
                          },
                          { 
                            title: 'PTR Records', 
                            records: url.dns_ptr_records || [],
                            description: 'Pointer records - Maps IP addresses to hostnames (reverse DNS)',
                            badge: 'bg-dark'
                          },
                          { 
                            title: 'SRV Records', 
                            records: url.dns_srv_records || [],
                            description: 'Service records - Specifies location of servers for specific services',
                            badge: 'bg-info'
                          }
                        ];

                        const hasAnyDNSRecords = dnsRecordTypes.some(
                          recordType => recordType.records && recordType.records.length > 0
                        );

                        return hasAnyDNSRecords ? (
                          <div>
                            <h6 className="text-danger mb-3">DNS Records</h6>
                            <div className="ms-3">
                              {dnsRecordTypes.map((recordType, index) => {
                                if (!recordType.records || recordType.records.length === 0) return null;
                                return (
                                  <div key={index} className="mb-3">
                                    <p className="mb-2">
                                      <Badge bg={recordType.badge.split('-')[1]} className="me-2">
                                        {recordType.title}
                                      </Badge>
                                      <small className="text-muted">{recordType.description}</small>
                                    </p>
                                    <div className="bg-dark p-2 rounded">
                                      {recordType.records.map((record, recordIndex) => (
                                        <div key={recordIndex} className="mb-1 font-monospace small">
                                          {record}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        ) : null;
                      })()}
                      {findings.length > 0 && (
                        <div>
                          <h6 className="text-danger mb-3">Technology Stack</h6>
                          <div className="ms-3">
                            {findings.map((finding, index) => (
                              <div key={index} className="mb-2 text-white">
                                {finding.info?.name || finding.template} -- {finding['matcher-name']?.toUpperCase()}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      <div>
                        <h6 className="text-danger mb-3">Crawled URLs</h6>
                        <div className="ms-3">
                          <Accordion>
                            <Accordion.Item eventKey="0">
                              <Accordion.Header>
                                <div className="d-flex align-items-center justify-content-between w-100">
                                  <div>
                                    <span className="text-white">
                                      Katana Results
                                    </span>
                                    <br/>
                                    <small className="text-muted">URLs discovered through crawling</small>
                                  </div>
                                  <Badge 
                                    bg={katanaUrls.length > 0 ? "info" : "secondary"}
                                    className="ms-2"
                                    style={{ fontSize: '0.8em' }}
                                  >
                                    {katanaUrls.length} URLs
                                  </Badge>
                                </div>
                              </Accordion.Header>
                              <Accordion.Body>
                                {katanaUrls.length > 0 ? (
                                  <div 
                                    className="bg-dark p-3 rounded font-monospace" 
                                    style={{ 
                                      maxHeight: '300px', 
                                      overflowY: 'auto',
                                      fontSize: '0.85em'
                                    }}
                                  >
                                    {katanaUrls.map((crawledUrl, index) => (
                                      <div key={index} className="mb-2 d-flex align-items-center">
                                        <span className="me-2">•</span>
                                        <span style={{ wordBreak: 'break-all' }}>
                                          <a 
                                            href={crawledUrl} 
                                            target="_blank" 
                                            rel="noopener noreferrer" 
                                            className="text-info text-decoration-none"
                                          >
                                            {crawledUrl}
                                          </a>
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-muted text-center py-3">
                                    No URLs were discovered during crawling
                                  </div>
                                )}
                              </Accordion.Body>
                            </Accordion.Item>
                          </Accordion>
                        </div>
                      </div>
                      <div className="mt-4">
                        <h6 className="text-danger mb-3">Discovered Endpoints</h6>
                        <div className="ms-3">
                          <Accordion>
                            <Accordion.Item eventKey="0">
                              <Accordion.Header>
                                <div className="d-flex align-items-center justify-content-between w-100">
                                  <div>
                                    <span className="text-white">
                                      Ffuf Results
                                    </span>
                                    <br/>
                                    <small className="text-muted">Endpoints discovered through fuzzing</small>
                                  </div>
                                  <Badge 
                                    bg={url.ffuf_results?.endpoints?.length > 0 ? "dark" : "secondary"}
                                    className="ms-2 text-white"
                                    style={{ fontSize: '0.8em' }}
                                  >
                                    {url.ffuf_results?.endpoints?.length || 0} Endpoints
                                  </Badge>
                                </div>
                              </Accordion.Header>
                              <Accordion.Body>
                                {url.ffuf_results?.endpoints?.length > 0 ? (
                                  <div 
                                    className="bg-dark p-3 rounded font-monospace" 
                                    style={{ 
                                      maxHeight: '300px', 
                                      overflowY: 'auto',
                                      fontSize: '0.85em'
                                    }}
                                  >
                                    {url.ffuf_results?.endpoints?.map((endpoint, index) => (
                                      <div key={index} className="mb-2 d-flex align-items-center">
                                        <Badge 
                                          bg={getStatusCodeColor(endpoint.status).bg}
                                          className={`me-2 text-${getStatusCodeColor(endpoint.status).text}`}
                                          style={{ fontSize: '0.8em', minWidth: '3em' }}
                                        >
                                          {endpoint.status}
                                        </Badge>
                                        <span style={{ wordBreak: 'break-all' }}>
                                          <a 
                                            href={`${url.url}/${endpoint.path}`} 
                                            target="_blank" 
                                            rel="noopener noreferrer" 
                                            className="text-info text-decoration-none"
                                          >
                                            /{endpoint.path}
                                          </a>
                                          <span className="ms-2 text-muted">
                                            <small>
                                              ({endpoint.size} bytes, {endpoint.words} words, {endpoint.lines} lines)
                                            </small>
                                          </span>
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-muted text-center py-3">
                                    No endpoints were discovered during fuzzing
                                  </div>
                                )}
                              </Accordion.Body>
                            </Accordion.Item>
                          </Accordion>
                        </div>
                      </div>
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