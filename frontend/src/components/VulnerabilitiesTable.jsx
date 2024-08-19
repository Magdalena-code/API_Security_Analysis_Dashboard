import React, { useState } from 'react';
import PropTypes from 'prop-types';

const OWASP_URLS = {
    "API1 - Broken Object Level Authorization": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "API2 - Broken Authentication": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "API3 - Broken Object Property Level Authorization": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "API4 - Unrestricted Resource Consumption": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "API5 - Broken Function Level Authorization": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    "API6 - Unrestricted Access to Sensitive Business Flows": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    "API7 - Server Side Request Forgery": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    "API8 - Security Misconfiguration": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    "API9 - Improper Inventory Management": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    "API10 - Unsafe Consumption of APIs": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"
};

const combineVulnerabilities = (vulnerabilities) => {
    const combined = vulnerabilities.reduce((acc, vuln) => {
        if (!acc[vuln.vuln_id]) {
            acc[vuln.vuln_id] = { ...vuln, owasp_names: [], owasp_urls: [] };
        }
        acc[vuln.vuln_id].owasp_names.push(vuln.owasp_name);
        acc[vuln.vuln_id].owasp_urls.push(OWASP_URLS[vuln.owasp_name] || '#');
        return acc;
    }, {});

    return Object.values(combined).map(vuln => ({
        ...vuln,
        owasp_names: vuln.owasp_names.join(', '),
        owasp_urls: [...new Set(vuln.owasp_urls)]
    }));
};

const VulnerabilitiesTable = ({ vulnerabilities, sortConfig, requestSort, getClassNamesFor }) => {
    const [expandedVulns, setExpandedVulns] = useState({});

    const priorityOrder = { 'high': 1, 'medium': 2, 'low': 3, 'informational': 4 };

    const sortedVulnerabilities = React.useMemo(() => {
        const combinedVulnerabilities = combineVulnerabilities(vulnerabilities);
        let sortableVulnerabilities = [...combinedVulnerabilities];
        if (sortConfig !== null) {
            sortableVulnerabilities.sort((a, b) => {
                if (sortConfig.key === 'prio_name') {
                    const aPriority = priorityOrder[a[sortConfig.key].toLowerCase()];
                    const bPriority = priorityOrder[b[sortConfig.key].toLowerCase()];
                    if (aPriority < bPriority) {
                        return sortConfig.direction === 'ascending' ? -1 : 1;
                    }
                    if (aPriority > bPriority) {
                        return sortConfig.direction === 'ascending' ? 1 : -1;
                    }
                    return 0;
                } else {
                    if (a[sortConfig.key] < b[sortConfig.key]) {
                        return sortConfig.direction === 'ascending' ? -1 : 1;
                    }
                    if (a[sortConfig.key] > b[sortConfig.key]) {
                        return sortConfig.direction === 'ascending' ? 1 : -1;
                    }
                    return 0;
                }
            });
        }
        return sortableVulnerabilities;
    }, [vulnerabilities, sortConfig]);

    const toggleDescription = (vulnId) => {
        setExpandedVulns(prev => ({
            ...prev,
            [vulnId]: !prev[vulnId]
        }));
    };

    return (
        <div>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                <tr>
                    <th onClick={() => requestSort('vuln_id')} className={getClassNamesFor('vuln_id')}>Vulnerability ID</th>
                    <th onClick={() => requestSort('vuln_name')} className={getClassNamesFor('vuln_name')}>Vulnerability Name</th>
                    <th onClick={() => requestSort('vuln_number')} className={getClassNamesFor('vuln_number')}>Vulnerability Count</th>
                    <th onClick={() => requestSort('prio_name')} className={getClassNamesFor('prio_name')}>Risk Level</th>
                    <th onClick={() => requestSort('owasp_name')} className={getClassNamesFor('owasp_name')}>OWASP Category</th>
                    <th>Description</th>
                </tr>
                </thead>
                <tbody>
                {sortedVulnerabilities.map((vuln, index) => (
                    <React.Fragment key={`${vuln.vuln_id}-${index}`}>
                        <tr style={{ borderBottom: '1px solid #ddd', backgroundColor: vuln.vuln_new ? '#f2dede' : 'white' }}>
                            <td>{vuln.vuln_id}</td>
                            <td>{vuln.vuln_name} {vuln.vuln_new && <span style={{ color: 'red' }}>NEW</span>}</td>
                            <td>{vuln.vuln_number}</td>
                            <td>{vuln.prio_name}</td>
                            <td>
                                {vuln.owasp_names.split(', ').map((name, i) => (
                                    <div key={i}>
                                        <a href={vuln.owasp_urls[i]} target="_blank" rel="noopener noreferrer">
                                            {name}
                                        </a>
                                    </div>
                                ))}
                            </td>
                            <td>
                                <div onClick={() => toggleDescription(vuln.vuln_id)} style={{ cursor: 'pointer', color: 'blue', textDecoration: 'underline' }}>
                                    {expandedVulns[vuln.vuln_id] ? '▼' : '▶'}
                                </div>
                            </td>
                        </tr>
                        {expandedVulns[vuln.vuln_id] && (
                            <tr>
                                <td colSpan="6" style={{ borderBottom: '1px solid #ddd', padding: '10px' }}>
                                    {vuln.vuln_description.replace(/<\/?p>/g, '')}
                                </td>
                            </tr>
                        )}
                    </React.Fragment>
                ))}
                </tbody>
                <tfoot>
                <tr>
                    <td colSpan="6" style={{ textAlign: 'left', padding: '10px', fontSize: '12px', color: '#666' }}>
                        Disclaimer: A vulnerability is labeled as NEW when it hasn't occurred in a scan in the span of one month.
                    </td>
                </tr>
                </tfoot>
            </table>
        </div>
    );
};

VulnerabilitiesTable.propTypes = {
    vulnerabilities: PropTypes.arrayOf(
        PropTypes.shape({
            vuln_id: PropTypes.number.isRequired,
            vuln_name: PropTypes.string.isRequired,
            vuln_number: PropTypes.number.isRequired,
            prio_name: PropTypes.string.isRequired,
            owasp_name: PropTypes.string.isRequired,
            scan_date: PropTypes.string.isRequired,
            scan_id: PropTypes.number.isRequired,
            scan_url: PropTypes.string.isRequired,
            tool_name: PropTypes.string.isRequired,
            vuln_description: PropTypes.string.isRequired,
            vuln_new: PropTypes.bool.isRequired
        })
    ).isRequired,
    sortConfig: PropTypes.object,
    requestSort: PropTypes.func.isRequired,
    getClassNamesFor: PropTypes.func.isRequired,
};

export default VulnerabilitiesTable;
