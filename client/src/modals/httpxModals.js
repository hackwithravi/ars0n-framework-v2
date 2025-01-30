import React from 'react';
import { Modal, Table, Badge } from 'react-bootstrap';

export const HttpxResultsModal = ({ showHttpxResultsModal, handleCloseHttpxResultsModal, httpxResults }) => {
  const parseResults = (results) => {
    if (!results) return [];
    try {
      // Split by newlines and parse each line as JSON
      return results.split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
    } catch (error) {
      console.error('Error parsing httpx results:', error);
      return [];
    }
  };

  const getStatusBadgeVariant = (status) => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'info';
    if (status >= 400 && status < 500) return 'warning';
    if (status >= 500) return 'danger';
    return 'secondary';
  };

  const parsedResults = parseResults(httpxResults?.result);

  return (
    <Modal data-bs-theme="dark" show={showHttpxResultsModal} onHide={handleCloseHttpxResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Live Web Servers</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover responsive>
          <thead>
            <tr>
              <th>URL</th>
              <th>Status Code</th>
              <th>Title</th>
              <th>Web Server</th>
              <th>Technologies</th>
              <th>Content Length</th>
            </tr>
          </thead>
          <tbody>
            {parsedResults.map((result, index) => (
              <tr key={index}>
                <td>
                  <a 
                    href={result.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-danger text-decoration-none"
                  >
                    {result.url}
                  </a>
                </td>
                <td>
                  <Badge bg={getStatusBadgeVariant(result.status_code)}>
                    {result.status_code}
                  </Badge>
                </td>
                <td>{result.title || '-'}</td>
                <td>{result.webserver || '-'}</td>
                <td>
                  {result.tech ? (
                    <div className="d-flex flex-wrap gap-1">
                      {result.tech.map((tech, i) => (
                        <Badge key={i} bg="secondary">{tech}</Badge>
                      ))}
                    </div>
                  ) : '-'}
                </td>
                <td>{result.content_length || '-'}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
}; 