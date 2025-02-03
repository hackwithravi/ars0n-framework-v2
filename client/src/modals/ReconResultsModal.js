import React from 'react';
import { Modal, Table, Badge } from 'react-bootstrap';

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

    const formatExecutionTime = (timeStr) => {
        if (!timeStr) return 'N/A';
        
        // Convert Go duration format to readable format
        try {
            // Remove 's' suffix if present
            timeStr = timeStr.replace('s', '');
            
            // Convert to number (seconds)
            const totalSeconds = parseFloat(timeStr);
            
            if (isNaN(totalSeconds)) return timeStr;

            const hours = Math.floor(totalSeconds / 3600);
            const minutes = Math.floor((totalSeconds % 3600) / 60);
            const seconds = Math.floor(totalSeconds % 60);
            const milliseconds = Math.round((totalSeconds % 1) * 1000);

            let formattedTime = '';
            
            if (hours > 0) formattedTime += `${hours}h `;
            if (minutes > 0) formattedTime += `${minutes}m `;
            if (seconds > 0 || milliseconds > 0) {
                formattedTime += `${seconds}`;
                if (milliseconds > 0) formattedTime += `.${milliseconds.toString().padStart(3, '0')}`;
                formattedTime += 's';
            }

            return formattedTime.trim() || '0s';
        } catch (e) {
            return timeStr;
        }
    };

    const getStatusBadge = (status) => {
        if (!status) return <Badge bg="secondary">N/A</Badge>;

        const statusColors = {
            'success': 'success',
            'completed': 'success',
            'error': 'danger',
            'pending': 'warning'
        };

        return (
            <Badge bg={statusColors[status] || 'secondary'}>
                {status.charAt(0).toUpperCase() + status.slice(1)}
            </Badge>
        );
    };

    const tools = [
        { name: 'Amass', results: amassResults, link: 'https://github.com/owasp-amass/amass' },
        { name: 'Sublist3r', results: sublist3rResults, link: 'https://github.com/aboul3la/Sublist3r' },
        { name: 'Assetfinder', results: assetfinderResults, link: 'https://github.com/tomnomnom/assetfinder' },
        { name: 'GAU', results: gauResults, link: 'https://github.com/lc/gau', tool: 'gau' },
        { name: 'CTL', results: ctlResults, link: 'https://github.com/pdiscoveryio/ctl' },
        { name: 'Subfinder', results: subfinderResults, link: 'https://github.com/projectdiscovery/subfinder' }
    ];

    return (
        <Modal data-bs-theme="dark" show={showReconResultsModal} onHide={handleCloseReconResultsModal} size="lg">
            <Modal.Header closeButton>
                <Modal.Title className="text-danger">Reconnaissance Results</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th className="text-center">Status</th>
                            <th className="text-center">Subdomains</th>
                            <th className="text-center">Execution Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tools.map((tool, index) => (
                            <tr key={index}>
                                <td>
                                    <a 
                                        href={tool.link}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-danger text-decoration-none"
                                    >
                                        {tool.name}
                                    </a>
                                </td>
                                <td className="text-center">
                                    {getStatusBadge(tool.results?.status)}
                                </td>
                                <td className="text-center">
                                    {getSubdomainCount(tool.results, tool.tool)}
                                </td>
                                <td className="text-center">
                                    {formatExecutionTime(tool.results?.execution_time)}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </Modal.Body>
        </Modal>
    );
}; 