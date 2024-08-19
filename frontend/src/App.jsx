import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import ScanPage from './components/ScanPage';
import ScanDetails from "./components/ScanDetails.jsx";
import Customize from "./components/Customize";
import './App.css';

function App() {
    return (
        <Router>
            <div>
                <Routes>
                    <Route path="/" element={<ScanPage />} exact />
                    <Route path="/scan/:scanId" element={<ScanDetails />} />
                    <Route path="/customize" element={<Customize />} />
                </Routes>
            </div>
        </Router>
    );
}

export default App;
