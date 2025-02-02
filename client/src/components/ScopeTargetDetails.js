import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Container, Row, Col, Button, Card, Table, Badge, Spinner } from 'react-bootstrap';
import { toast } from 'react-toastify';

const ScopeTargetDetails = () => {
    const [scopeTarget, setScopeTarget] = useState(null);
    const [ctlScans, setCtlScans] = useState([]);
    const [subfinderScans, setSubfinderScans] = useState([]);
    const [isCtlScanning, setIsCtlScanning] = useState(false);
    const [isSubfinderScanning, setIsSubfinderScanning] = useState(false);
    const { id } = useParams();

    useEffect(() => {
        fetchScopeTarget();
        fetchCtlScans();
        fetchSubfinderScans();
        const interval = setInterval(() => {
            if (isCtlScanning) {
                fetchCtlScans();
            }
            if (isSubfinderScanning) {
                fetchSubfinderScans();
            }
        }, 5000);
        return () => clearInterval(interval);
    }, [id, isCtlScanning, isSubfinderScanning]);

    const fetchScopeTarget = async () => {
        try {
            const response = await fetch(`http://localhost:8080/scopetarget/${id}`);
            if (!response.ok) throw new Error('Failed to fetch scope target');
            const data = await response.json();
            setScopeTarget(data);
        } catch (error) {
            console.error('Error fetching scope target:', error);
            toast.error('Failed to fetch scope target details');
        }
    };

    const fetchCtlScans = async () => {
        try {
            const response = await fetch(`http://localhost:8080/scopetarget/${id}/scans/ctl`);
            if (!response.ok) throw new Error('Failed to fetch CTL scans');
            const data = await response.json();
            setCtlScans(data);
            setIsCtlScanning(data.some(scan => scan.status === 'pending'));
        } catch (error) {
            console.error('Error fetching CTL scans:', error);
            toast.error('Failed to fetch CTL scan history');
        }
    };

    const fetchSubfinderScans = async () => {
        try {
            const response = await fetch(`http://localhost:8080/scopetarget/${id}/scans/subfinder`);
            if (!response.ok) throw new Error('Failed to fetch Subfinder scans');
            const data = await response.json();
            setSubfinderScans(data);
            setIsSubfinderScanning(data.some(scan => scan.status === 'pending'));
        } catch (error) {
            console.error('Error fetching Subfinder scans:', error);
            toast.error('Failed to fetch Subfinder scan history');
        }
    };

    const initiateCtlScan = async () => {
        if (!scopeTarget) return;
        const domain = scopeTarget.scope_target.replace('*.', '');
        try {
            const response = await fetch('http://localhost:8080/ctl/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fqdn: domain })
            });
            if (!response.ok) throw new Error('Failed to initiate CTL scan');
            setIsCtlScanning(true);
            toast.success('CTL scan initiated successfully');
        } catch (error) {
            console.error('Error initiating CTL scan:', error);
            toast.error('Failed to initiate CTL scan');
        }
    };

    const initiateSubfinderScan = async () => {
        if (!scopeTarget) return;
        const domain = scopeTarget.scope_target.replace('*.', '');
        try {
            const response = await fetch('http://localhost:8080/subfinder/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fqdn: domain })
            });
            if (!response.ok) throw new Error('Failed to initiate Subfinder scan');
            setIsSubfinderScanning(true);
            toast.success('Subfinder scan initiated successfully');
        } catch (error) {
            console.error('Error initiating Subfinder scan:', error);
            toast.error('Failed to initiate Subfinder scan');
        }
    };

    const renderScanResults = (scans, title) => {
        if (!scans || scans.length === 0) return null;
        return (
            <Card className="mt-4">
                <Card.Header>{title} Results</Card.Header>
                <Card.Body>
                    <Table striped bordered hover>
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Status</th>
                                <th>Created At</th>
                                <th>Results</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scans.map(scan => (
                                <tr key={scan.scan_id}>
                                    <td>{scan.scan_id}</td>
                                    <td>
                                        <Badge bg={scan.status === 'success' ? 'success' : scan.status === 'pending' ? 'warning' : 'danger'}>
                                            {scan.status}
                                        </Badge>
                                    </td>
                                    <td>{new Date(scan.created_at).toLocaleString()}</td>
                                    <td>
                                        {scan.result ? (
                                            <pre style={{ maxHeight: '200px', overflow: 'auto' }}>
                                                {scan.result}
                                            </pre>
                                        ) : scan.status === 'pending' ? (
                                            <Spinner animation="border" size="sm" />
                                        ) : (
                                            'No results'
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </Table>
                </Card.Body>
            </Card>
        );
    };

    if (!scopeTarget) {
        return <Container><Spinner animation="border" /></Container>;
    }

    return (
        <Container>
            <Row className="mt-4">
                <Col>
                    <h2>Scope Target Details</h2>
                    <Card>
                        <Card.Body>
                            <Card.Title>{scopeTarget.scope_target}</Card.Title>
                            <Card.Text>
                                <strong>Type:</strong> {scopeTarget.type}<br />
                                <strong>Created At:</strong> {new Date(scopeTarget.created_at).toLocaleString()}
                            </Card.Text>
                            <Button 
                                variant="primary" 
                                onClick={initiateCtlScan}
                                disabled={isCtlScanning}
                                className="me-2"
                            >
                                {isCtlScanning ? (
                                    <>
                                        <Spinner animation="border" size="sm" className="me-2" />
                                        CTL Scan Running...
                                    </>
                                ) : 'Run CTL Scan'}
                            </Button>
                            <Button 
                                variant="primary" 
                                onClick={initiateSubfinderScan}
                                disabled={isSubfinderScanning}
                            >
                                {isSubfinderScanning ? (
                                    <>
                                        <Spinner animation="border" size="sm" className="me-2" />
                                        Subfinder Scan Running...
                                    </>
                                ) : 'Run Subfinder Scan'}
                            </Button>
                        </Card.Body>
                    </Card>
                </Col>
            </Row>
            {renderScanResults(ctlScans, 'CTL')}
            {renderScanResults(subfinderScans, 'Subfinder')}
        </Container>
    );
};

export default ScopeTargetDetails; 