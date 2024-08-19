import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const API_URL = import.meta.env.VITE_API_URL;

function ScanList() {
    const [scans, setScans] = useState([]);

    useEffect(() => {
        const fetchScans = async () => {
            try {
                const response = await axios.get(`${API_URL}/scans`);
                console.log('Response:', response);
                console.log('Response data:', response.data);
                setScans(response.data);
            } catch (error) {
                console.error('Failed to fetch scans:', error);
            }
        };

        fetchScans();
    }, []);  // Empty dependency array means this effect runs once on mount

    console.log('Requesting:', `${API_URL}/scans`);

    return (
        <div>
        <div>
            <h1>Previous scans</h1>
            <ul>
                {scans.map(scan => (
                    <li key={scan.scan_id}>
                        <Link to={`/scan/${scan.scan_id}`}>{scan.scan_date} ({scan.scan_url})</Link>
                    </li>
                ))}
            </ul>
        </div>
        </div>
    );
}

export default ScanList;
