import React from 'react';
import { Modal, Table } from 'react-bootstrap';

export const ReconResultsModal = ({
    showReconResultsModal,
    handleCloseReconResultsModal,
    amassResults,
    sublist3rResults,
    assetfinderResults,
    gauResults,
    ctlResults,
    subfinderResults
}) => {
    const getSubdomainCount = (results, tool) => {
        if (!results || !results.result) return 0;

        if (tool === 'gau') {
            try {
                const lines = results.result.split('\n').filter(line => line.trim());
                const uniqueSubdomains = new Set();
                lines.forEach(line => {
                    try {
                        const data = JSON.parse(line);
                        if (data.url) {
                            const url = new URL(data.url);
                            uniqueSubdomains.add(url.hostname);
                        }
                    } catch (e) {}
                });
                return uniqueSubdomains.size;
            } catch (e) {
                return 0;
            }
        }

        return results.result.split('\n').filter(line => line.trim()).length;
    };

    const getAmassSubdomainCount = (results) => {
        if (!results || !results.result) return 0;
        
        // Get the base domain from the scan domain
        const baseDomain = results.domain;
        if (!baseDomain) return 0;

        // Split the results into lines and count only valid subdomains
        const lines = results.result.split('\n');
        const uniqueSubdomains = new Set();

        lines.forEach(line => {
            // Skip empty lines
            if (!line.trim()) return;

            // If the line contains a subdomain (ends with the base domain), add it
            if (line.includes(baseDomain)) {
                // Extract potential subdomain from the line
                const match = line.match(/([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
                if (match && match[1].endsWith(baseDomain)) {
                    uniqueSubdomains.add(match[1]);
                }
            }
        });

        return uniqueSubdomains.size;
    };

    return (
        <Modal data-bs-theme="dark" show={showReconResultsModal} onHide={handleCloseReconResultsModal} size="lg">
            <Modal.Header closeButton>
                <Modal.Title className="text-danger">Recon Results</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Status</th>
                            <th>Subdomains Found</th>
                            <th>Execution Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Amass</td>
                            <td>{amassResults?.status || "N/A"}</td>
                            <td>{getAmassSubdomainCount(amassResults)}</td>
                            <td>{amassResults?.execution_time || "N/A"}</td>
                        </tr>
                        <tr>
                            <td>Sublist3r</td>
                            <td>{sublist3rResults?.status || "N/A"}</td>
                            <td>{getSubdomainCount(sublist3rResults)}</td>
                            <td>{sublist3rResults?.execution_time || "N/A"}</td>
                        </tr>
                        <tr>
                            <td>Assetfinder</td>
                            <td>{assetfinderResults?.status || "N/A"}</td>
                            <td>{getSubdomainCount(assetfinderResults)}</td>
                            <td>{assetfinderResults?.execution_time || "N/A"}</td>
                        </tr>
                        <tr>
                            <td>GAU</td>
                            <td>{gauResults?.status || "N/A"}</td>
                            <td>{getSubdomainCount(gauResults, 'gau')}</td>
                            <td>{gauResults?.execution_time || "N/A"}</td>
                        </tr>
                        <tr>
                            <td>CTL</td>
                            <td>{ctlResults?.status || "N/A"}</td>
                            <td>{getSubdomainCount(ctlResults)}</td>
                            <td>{ctlResults?.execution_time || "N/A"}</td>
                        </tr>
                        <tr>
                            <td>Subfinder</td>
                            <td>{subfinderResults?.status || "N/A"}</td>
                            <td>{getSubdomainCount(subfinderResults)}</td>
                            <td>{subfinderResults?.execution_time || "N/A"}</td>
                        </tr>
                    </tbody>
                </Table>
            </Modal.Body>
        </Modal>
    );
}; 