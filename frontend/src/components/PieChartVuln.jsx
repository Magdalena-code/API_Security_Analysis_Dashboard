import React from 'react';
import { Pie } from 'react-chartjs-2';
import PropTypes from 'prop-types';
import {ArcElement, CategoryScale, Chart as ChartJS, Legend, LinearScale, Title, Tooltip} from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, Title);


function PieChartVuln({ vulnerabilities }) {
    const owaspCounts = vulnerabilities.reduce((acc, vuln) => {
        const owaspName = vuln.owasp_name;
        if (acc[owaspName]) {
            acc[owaspName]++;
        } else {
            acc[owaspName] = 1;
        }
        return acc;
    }, {});

    const data = {
        labels: Object.keys(owaspCounts),
        datasets: [
            {
                label: 'OWASP Top 10 Distribution',
                data: Object.values(owaspCounts),
                backgroundColor: [
                    '#FF7F50',
                    '#8B008B',
                    '#ADFF2F',
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#48D1CC',
                    '#FFC0CB',
                    '#008080',
                    '#ADD8E6',
                ],
                hoverBackgroundColor: [
                    '#FF7F50',
                    '#8B008B',
                    '#ADFF2F',
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#48D1CC',
                    '#FFC0CB',
                    '#008080',
                    '#ADD8E6',
                ],
            },
        ],
    };

    return (
        <div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '800px'}}>
            <div style={{width: '500px', height: '500px'}}>
                <h2 style={{textAlign: 'center'}}>OWASP API-Security Top 10 Distribution</h2>
                <Pie data={data}/>
            </div>
        </div>
    );
}

PieChartVuln.propTypes = {
    vulnerabilities: PropTypes.arrayOf(PropTypes.shape({
        vuln_id: PropTypes.number.isRequired,
        vuln_name: PropTypes.string.isRequired,
        vuln_number: PropTypes.number.isRequired,
        prio_name: PropTypes.string.isRequired,
        owasp_name: PropTypes.string.isRequired,
        scan_date: PropTypes.string.isRequired,
        scan_id: PropTypes.number.isRequired,
        scan_url: PropTypes.string.isRequired,
        tool_name: PropTypes.string.isRequired,
    })).isRequired,
};


export default PieChartVuln;
