import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import PieChartVuln from "./PieChartVuln.jsx";
import VulnerabilityCircles from "./VulnerabilityCircles.jsx";
import CirclePackingDiagram from "./CirclePackingDiagram.jsx";
import RiskLevelBarChart from "./RiskLevelBarChart.jsx";
import ScatterPlot from "./ScatterPlot.jsx";
import Tachometer from "./Tachometer.jsx";
import TimelineChart from "./TimelineChart.jsx";
import VulnerabilitiesTable from "./VulnerabilitiesTable.jsx";
import VulnerabilityTrendChart from "./VulnerabilityTrendChart.jsx";
import RiskTimeline from "./RiskTimeLine.jsx";
import NewOldVulnerabilitiesChart from "./NewOldVulnerabilitiesChart.jsx";

const API_URL = import.meta.env.VITE_API_URL;

function ScanDetails() {
    const { scanId } = useParams();
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [scanInfo, setScanInfo] = useState(null);
    const [hierarchyData, setHierarchyData] = useState(null);
    const [scatterPlotData, setScatterPlotData] = useState([]);
    const [sortConfig, setSortConfig] = useState({ key: null, direction: 'ascending' });
    const [weights, setWeights] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchVulnerabilities = async () => {
            try {
                const response = await axios.get(`${API_URL}/vulnerabilities?scan_id=${scanId}`);
                setVulnerabilities(response.data);

                if (response.data.length > 0) {
                    const scanData = {
                        scan_date: response.data[0].scan_date,
                        scan_url: response.data[0].scan_url,
                        scan_active: response.data[0].scan_active,
                        scan_id: scanId,
                        scan_new: response.data[0].scan_new
                    };
                    setScanInfo(scanData);
                }

                const transformedData = transformDataToHierarchy(response.data);
                setHierarchyData(transformedData);

                const scatterData = transformDataToScatterPlot(response.data);
                setScatterPlotData(scatterData);

                const weightResponse = await axios.get(`${API_URL}/customisation`);
                console.log('Weight Response Data:', weightResponse.data);
                const weights = weightResponse.data.map(weight => ({
                    ...weight,
                    owasp_name: weight.owasp_cat, // Map owasp_cat to owasp_name
                }));

                setWeights(weights);

            } catch (error) {
                console.error('Failed to fetch vulnerabilities or weights:', error);
            }
        };

        fetchVulnerabilities();
    }, [scanId]);

    const requestSort = (key) => {
        let direction = 'ascending';
        if (sortConfig && sortConfig.key === key && sortConfig.direction === 'ascending') {
            direction = 'descending';
        }
        setSortConfig({ key, direction });
    };

    const getClassNamesFor = (key) => {
        if (!sortConfig) {
            return;
        }
        return sortConfig.key === key ? sortConfig.direction : undefined;
    };

    const calculateOverview = (vulnerabilities, weights) => {
        const uniqueVulnerabilities = filterUniqueVulnerabilities(vulnerabilities, weights);
        const totalCount = uniqueVulnerabilities.length;
        const categoryCount = uniqueVulnerabilities.reduce((acc, vuln) => {
            acc[vuln.owasp_name] = (acc[vuln.owasp_name] || 0) + 1;
            return acc;
        }, {});
        const numberOneCategory = Object.keys(categoryCount).reduce((a, b) => categoryCount[a] > categoryCount[b] ? a : b, '');

        return { totalCount, numberOneCategory };
    };

    const filterUniqueVulnerabilities = (vulnerabilities, weights = []) => {
        const weightMapping = {};
        weights.forEach(weight => {
            const owaspName = weight.owasp_name;
            weightMapping[owaspName] = weight.weight;
        });

        console.log('Weight Mapping:', weightMapping); // Debugging log

        const uniqueVulnMap = {};
        vulnerabilities.forEach(vuln => {
            const owaspName = vuln.owasp_name ? vuln.owasp_name : '';
            const currentWeight = weightMapping[owaspName] || 0;

            console.log(`Vulnerability: ${vuln.vuln_name}, OWASP Name: ${owaspName}, Weight: ${currentWeight}`); // Debugging log

            if (uniqueVulnMap[vuln.vuln_id]) {
                const existingWeight = uniqueVulnMap[vuln.vuln_id].highestWeight || 0;
                if (currentWeight > existingWeight) {
                    uniqueVulnMap[vuln.vuln_id] = { ...vuln, highestWeight: currentWeight };
                }
            } else {
                uniqueVulnMap[vuln.vuln_id] = { ...vuln, highestWeight: currentWeight };
            }
        });

        console.log('Filtered Unique Vulnerabilities:', uniqueVulnMap); // Debugging log
        return Object.values(uniqueVulnMap);
    };

    const calculateRiskScore = (vulnerability) => {
        const priorityOrder = { 'high': 3, 'medium': 2, 'low': 1, 'informational': 0 };
        const priority = priorityOrder[vulnerability.prio_name ? vulnerability.prio_name.toLowerCase() : 'NAN'] || 0;
        const weight = vulnerability.highestWeight || 0;

        const riskScore = priority * weight;
        console.log(`Risk Score for ${vulnerability.vuln_name}: Priority(${priority}) * Weight(${weight}) = ${riskScore}`); // Debugging log
        return riskScore;
    };

    const findMostSevereVulnerabilities = (vulnerabilities) => {
        const uniqueVulnerabilities = filterUniqueVulnerabilities(vulnerabilities, weights);

        if (uniqueVulnerabilities.length === 0) return [];

        const maxRiskScore = Math.max(...uniqueVulnerabilities.map(vuln => calculateRiskScore(vuln)));

        return uniqueVulnerabilities.filter(vuln => calculateRiskScore(vuln) === maxRiskScore);
    };

    const { totalCount, numberOneCategory } = calculateOverview(vulnerabilities, weights);
    const mostSevereVulnerabilities = findMostSevereVulnerabilities(vulnerabilities);

    if (!scanInfo || !hierarchyData || scatterPlotData.length === 0 || weights.length === 0) return <p>Loading...</p>;

    const scanType = scanInfo.scan_active ? 'Active' : 'Passive';

    return (
        <div>
            <button style={{float: 'left'}} onClick={() => navigate('/')}>Go Back to Scan Page</button>
            <h1>Found Vulnerabilities</h1>
            <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <div>
                    <div style={{
                        border: '1px solid #000',
                        padding: '10px',
                        width: '350px',
                        fontFamily: 'Arial, sans-serif'
                    }}>
                        <h2 style={{textAlign: 'center'}}>Quick Overview</h2>
                        <p><strong>Scan-Date:</strong> {scanInfo.scan_date}</p>
                        <p><strong>Scan-URL:</strong> <a href={scanInfo.scan_url}>{scanInfo.scan_url}</a></p>
                        <p><strong>Scan Type:</strong> {scanType}</p>
                        <p><strong>Overall Vulnerability Count:</strong> {totalCount}</p>
                        <p><strong>Number One Category:</strong> {numberOneCategory}</p>
                        <p><strong>Most Severe Vulnerability:</strong>
                            {mostSevereVulnerabilities.length > 0 ? mostSevereVulnerabilities.map((vuln, index) => (
                                <span key={index}>
                                    {vuln.vuln_name}{index < mostSevereVulnerabilities.length - 1 ? ', ' : ''}
                                </span>
                            )) : 'N/A'}
                        </p>
                    </div>
                </div>
                <div>
                    <Tachometer vulnerabilities={vulnerabilities} weights={weights}/>
                </div>
            </div>
            <VulnerabilitiesTable
                vulnerabilities={vulnerabilities}
                sortConfig={sortConfig}
                requestSort={requestSort}
                getClassNamesFor={getClassNamesFor}
                style={{marginBottom: '20px'}}
            />
            <h2 style={{textAlign: 'center', fontWeight: 'bold', fontSize: '30px', fontStyle: 'italic'}}>Timelines</h2>
            <div style={{height: '50px'}}></div>
            <TimelineChart scanUrl={scanInfo.scan_url}
                           currentScanDate={new Date(scanInfo.scan_date).toISOString().split('T')[0]}/>
            <div style={{height: '50px'}}></div>
            <RiskTimeline scanUrl={scanInfo.scan_url}
                          currentScanDate={new Date(scanInfo.scan_date).toISOString().split('T')[0]} weights={weights}/>
            <div style={{border: '1px solid lightgrey', padding: '10px', marginBottom: '20px'}}>
                <VulnerabilityTrendChart scanUrl={scanInfo.scan_url}
                                         currentScanDate={new Date(scanInfo.scan_date).toISOString().split('T')[0]}/>
            </div>
            <div>
                <NewOldVulnerabilitiesChart scanUrl={scanInfo.scan_url}
                                            currentScanDate={new Date(scanInfo.scan_date).toISOString().split('T')[0]}/>
            </div>
            <h2 style={{
                textAlign: 'center',
                fontWeight: 'bold',
                fontSize: '30px',
                fontStyle: 'italic'
            }}>Distributions</h2>
            <div style={{border: '1px solid lightgrey', padding: '10px', marginBottom: '20px'}}>
                <PieChartVuln vulnerabilities={vulnerabilities}/>
            </div>
            <div>
                <VulnerabilityCircles vulnerabilities={vulnerabilities}/>
            </div>
            <div style={{border: '1px solid lightgrey', padding: '10px', marginBottom: '20px'}}>
                <CirclePackingDiagram data={hierarchyData}/>
            </div>
            <h2 style={{textAlign: 'center', fontWeight: 'bold', fontSize: '30px', fontStyle: 'italic'}}>Risklevels</h2>
            <div style={{border: '1px solid lightgrey', padding: '10px', marginBottom: '20px'}}>
                <RiskLevelBarChart vulnerabilities={vulnerabilities}/>
            </div>
            <div>
                <ScatterPlot data={scatterPlotData}/>
            </div>
        </div>
    );
}

const transformDataToHierarchy = (vulnerabilities) => {
    const hierarchy = {
        name: "OWASP Categories",
        children: []
    };

    const categories = {};

    vulnerabilities.forEach(vuln => {
        if (!categories[vuln.owasp_name]) {
            categories[vuln.owasp_name] = {
                name: vuln.owasp_name,
                count: 0,
                children: []
            };
        }

        categories[vuln.owasp_name].count += 1;
        categories[vuln.owasp_name].children.push({
            name: vuln.vuln_name,
            value: 1
        });
    });

    Object.values(categories).forEach(category => {
        category.value = category.count;
        delete category.count;
    });

    hierarchy.children = Object.values(categories);

    return hierarchy;
};

const transformDataToScatterPlot = (vulnerabilities) => {
    const consolidatedVulnerabilities = consolidateVulnerabilities(vulnerabilities);

    const priorityMapping = {
        "informational": 1,
        "low": 2,
        "medium": 3,
        "high": 4
    };

    return consolidatedVulnerabilities.map(vuln => ({
        vuln_name: vuln.vuln_name,
        priority: priorityMapping[vuln.priority],
        owasp_names: vuln.owasp_names
    }));
};

const consolidateVulnerabilities = (vulnerabilities) => {
    const consolidated = {};

    vulnerabilities.forEach(vuln => {
        if (!consolidated[vuln.vuln_id]) {
            consolidated[vuln.vuln_id] = {
                vuln_id: vuln.vuln_id,
                vuln_name: vuln.vuln_name,
                priority: vuln.prio_name.toLowerCase(),
                owasp_names: [vuln.owasp_name]
            };
        } else {
            consolidated[vuln.vuln_id].owasp_names.push(vuln.owasp_name);
        }
    });

    return Object.values(consolidated).map(vuln => ({
        vuln_name: vuln.vuln_name,
        priority: vuln.priority,
        owasp_names: vuln.owasp_names
    }));
};

export default ScanDetails;
