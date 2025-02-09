import React from 'react';
import { Modal, Table, Badge } from 'react-bootstrap';

const SSLMetadataModal = ({
  showSSLMetadataModal,
  handleCloseSSLMetadataModal,
  targetURLs
}) => {
  return (
    <Modal
      data-bs-theme="dark"
      show={showSSLMetadataModal}
      onHide={handleCloseSSLMetadataModal}
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">SSL Metadata Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover>
          <thead>
            <tr>
              <th>URL</th>
              <th>SSL Issues</th>
            </tr>
          </thead>
          <tbody>
            {targetURLs.map((url) => {
              const sslIssues = [];
              if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
              if (url.has_expired_ssl) sslIssues.push('Expired SSL');
              if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
              if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
              if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
              if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');
              if (url.has_wildcard_tls) sslIssues.push('Wildcard TLS');

              return (
                <tr key={url.id}>
                  <td>{url.url}</td>
                  <td>
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
                      <span className="text-success">No SSL Issues Found</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
};

export default SSLMetadataModal; 