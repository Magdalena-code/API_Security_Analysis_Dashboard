import React, { useState } from 'react';
import axios from 'axios';
import './ScanPage.css';
import ScanList from './ScanList.jsx';
import { Link } from 'react-router-dom';

const API_URL = import.meta.env.VITE_API_URL;

function ScanPage() {
    const [file, setFile] = useState(null);
    const [url, setUrl] = useState('');
    const [isUploading, setIsUploading] = useState(false);
    const [isScanning, setIsScanning] = useState(false);

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleUrlChange = (event) => {
        setUrl(event.target.value);
    };

    const handleUploadAndScan = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        setIsUploading(true);
        alert('Uploading and scanning the file - this might take a few moments.');

        try {
            const response = await axios.post(`${API_URL}/run-active-scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });

            if (response.status === 200) {
                alert('File scanned successfully!');
            } else {
                alert(`Failed to scan file: ${response.data.error}`);
            }
        } catch (error) {
            console.error('Error scanning file:', error);
            if (error.response && error.response.data && error.response.data.error) {
                alert(`Failed to scan file: ${error.response.data.error}`);
            } else {
                alert('Failed to scan file');
            }
        } finally {
            setIsUploading(false);
        }
    };

    const handleUrlScan = async () => {
        if (!url) {
            alert('Please enter a URL');
            return;
        }
        alert('Scan started - this might take a few moments.');
        setIsScanning(true);
        try {
            const response = await axios.post(`${API_URL}/run-passive-scan`, { url });

            if (response.status === 200) {
                alert('Scan ran successfully!');
            } else {
                alert(`Failed to start scan: ${response.data.error}`);
            }
        } catch (error) {
            console.error('Error starting scan:', error);
            if (error.response && error.response.data && error.response.data.error) {
                alert(`Failed to start scan: ${error.response.data.error}`);
            } else {
                alert('Failed to start scan');
            }
        } finally {
            setIsScanning(false);
        }
    };

    return (
        <div className="start-scan-container">
            <h1>Start New API Scan</h1>
            <div className="scan-options">
                <div className="scan-option">
                    <h2>Active Scan</h2>
                    <input
                        type="file"
                        className="start-scan-input"
                        onChange={handleFileChange}
                        accept=".json, .yaml"
                    />
                    <button className="start-scan-button" onClick={handleUploadAndScan} disabled={isUploading}>
                        {isUploading ? 'Scanning...' : 'Upload and Start Active Scan'}
                    </button>
                </div>
                <div className="scan-option">
                    <h2>Passive Scan</h2>
                    <input
                        type="text"
                        className="start-scan-input"
                        value={url}
                        onChange={handleUrlChange}
                        placeholder="Enter URL here (e.g., http://example.com)"
                    />
                    <button className="start-scan-button" onClick={handleUrlScan} disabled={isScanning}>
                        {isScanning ? 'Scanning...' : 'Start Passive Scan'}
                    </button>
                </div>
            </div>
            <ScanList />
            <Link to="/customize">
                <button type="button" className="customize-button">
                    Customize
                </button>
            </Link>
        </div>
    );
}

export default ScanPage;
