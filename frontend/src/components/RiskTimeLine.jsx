import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL;

function RiskTimeline({ scanUrl, currentScanDate, weights }) {
    const svgRef = useRef(null);
    const [data, setData] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get(`${API_URL}/vulnerabilities?scan_url=${scanUrl}`);
                console.log('Fetched data:', response.data); // Debugging log

                const riskData = calculateRiskData(response.data, weights);
                console.log('Risk data:', riskData); // Debugging log

                setData(riskData);
            } catch (error) {
                console.error('Failed to fetch scan data:', error);
            }
        };

        fetchData();
    }, [scanUrl, weights]);

    console.log('Current Scan Date:', currentScanDate);

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
        const priorityOrder = { 'high': 4, 'medium': 3, 'low': 2, 'informational': 1 };
        const priority = priorityOrder[vulnerability.prio_name ? vulnerability.prio_name.toLowerCase() : 'NAN'] || 0;
        const weight = vulnerability.highestWeight || 0;

        const riskScore = priority * weight;
        console.log(`Risk Score for ${vulnerability.vuln_name}: Priority(${priority}) * Weight(${weight}) = ${riskScore}`); // Debugging log
        return riskScore;
    };

    const calculateRiskData = (scans, weights) => {
        if (!Array.isArray(scans)) {
            console.error('Invalid data format. Expected an array of scans.');
            return [];
        }

        const scanMap = {};
        scans.forEach(scan => {
            const scanDate = new Date(scan.scan_date);
            const scanDateString = scanDate.toISOString().split('T')[0];
            const scanDateWithoutTime = new Date(scanDate.getFullYear(), scanDate.getMonth(), scanDate.getDate());

            if (!scanMap[scanDateString]) {
                scanMap[scanDateString] = {
                    date: scanDateWithoutTime,
                    vulnerabilities: [],
                    scan_id: scan.scan_id,
                    scan_active: scan.scan_active
                };
            }

            scanMap[scanDateString].vulnerabilities.push(scan);
        });

        return Object.values(scanMap).map(scan => {
            const uniqueVulnerabilities = filterUniqueVulnerabilities(scan.vulnerabilities, weights);

            const totalBaseRiskScore = uniqueVulnerabilities.reduce((total, vuln) => {
                return total + calculateRiskScore(vuln);
            }, 0);

            const scalingFactor = 1 + (uniqueVulnerabilities.length - 1) * 0.5;

// Adjusted risk score with scaling factor so that the more vulnerabilities the higher the risk score is
            const adjustedRiskScore = totalBaseRiskScore * scalingFactor;

            const maxPriority = 4;
            const maxWeight = 100;
            const maxPossibleBaseScore = uniqueVulnerabilities.length * maxPriority * maxWeight;

            const normalizedRiskScore = (adjustedRiskScore / maxPossibleBaseScore) * 100;

            return {
                date: scan.date,
                risk_percentage: normalizedRiskScore,
                scan_id: scan.scan_id,
                scan_active: scan.scan_active
            };
        }).sort((a, b) => a.date - b.date);
    };

    useEffect(() => {
        if (data.length === 0) return;

        const margin = { top: 30, right: 20, bottom: 100, left: 70 };
        const width = Math.max(data.length * 50, 1500) - margin.left - margin.right; // Adjust width based on data length
        const height = 600 - margin.top - margin.bottom;

        const svg = d3.select(svgRef.current);
        svg.selectAll('*').remove();

        const chart = svg
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        chart.append('text')
            .attr('x', width / 2)
            .attr('y', -10)
            .attr('text-anchor', 'middle')
            .style('font-size', '24px')
            .style('font-weight', 'bold')
            .text('Risk Percentage Timeline');

        data.forEach(d => {
            d.date = new Date(d.date);
        });

        const x = d3.scaleTime()
            .domain([d3.timeDay.offset(d3.min(data, d => d.date), -1), d3.timeDay.offset(d3.max(data, d => d.date), 1)])
            .range([0, width]);

        const y = d3.scaleLinear()
            .domain([0, 100])
            .nice()
            .range([height, 0]);

        const timeSpan = d3.max(data, d => d.date) - d3.min(data, d => d.date);
        const oneDay = 24 * 60 * 60 * 1000; // hours*minutes*seconds*milliseconds
        const oneMonth = oneDay * 30;
        const threeMonths = oneDay * 90;
        const nineMonths = threeMonths * 3;

        let tickFormat;
        let tickValue;

        if (timeSpan <= oneMonth) {
            tickFormat = d3.timeFormat("%Y-%m-%d");
            tickValue = d3.timeDay.every(1);
        } else if (timeSpan <= threeMonths) {
            tickFormat = d3.timeFormat("%Y-%m-%d");
            tickValue = d3.timeDay.every(2);
        } else if (timeSpan <= nineMonths) {
            tickFormat = d3.timeFormat("%Y-%m-%d");
            tickValue = d3.timeWeek.every(1);
        } else {
            tickFormat = d3.timeFormat("%Y-%m");
            tickValue = d3.timeMonth.every(1);
        }

        const xAxis = d3.axisBottom(x)
            .ticks(tickValue)
            .tickFormat(tickFormat);

        const yAxis = d3.axisLeft(y)
            .ticks(10)
            .tickFormat(d3.format("d"));

        chart.append('g')
            .attr('transform', `translate(0,${height})`)
            .call(xAxis)
            .selectAll('text')
            .attr('transform', 'rotate(-45)')
            .style('text-anchor', 'end')
            .attr('dx', '-0.8em')
            .attr('dy', '0.15em')
            .style('font-size', '12px');

        chart.append('g')
            .call(yAxis)
            .selectAll("text")
            .style("font-size", "16px");

        chart.append('text')
            .attr('transform', 'rotate(-90)')
            .attr('y', 0 - margin.left)
            .attr('x', 0 - (height / 2))
            .attr('dy', '1em')
            .style('text-anchor', 'middle')
            .style('font-size', '16px')
            .text('Risk Percentage');

        const line = d3.line()
            .x(d => x(d.date))
            .y(d => y(d.risk_percentage));

        chart.append('path')
            .datum(data)
            .attr('fill', 'none')
            .attr('stroke', 'steelblue')
            .attr('stroke-width', 2)
            .attr('d', line);

        const currentScanDateObj = new Date(currentScanDate);
        currentScanDateObj.setHours(0, 0, 0, 0);

        chart.selectAll('path.point')
            .data(data)
            .enter()
            .append('path')
            .attr('class', 'point')
            .attr('transform', d => `translate(${x(d.date)},${y(d.risk_percentage)})`)
            .attr('d', d3.symbol()
                .type(d => d.scan_active ? d3.symbolStar : d3.symbolCircle) // Star for active, Circle for passive
                .size(100))
            .attr('fill', d => {
                const dDate = new Date(d.date);
                dDate.setHours(0, 0, 0, 0);
                return dDate.getTime() === currentScanDateObj.getTime() ? 'red' : 'steelblue';
            })
            .on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('visibility', 'visible')
                    .html(`Date: ${d.date.toLocaleDateString()}<br>Risk Percentage: ${d.risk_percentage.toFixed(2)}%`)
                    .style('left', `${event.pageX + 10}px`)
                    .style('top', `${event.pageY + 10}px`);
            })
            .on('mouseout', () => {
                d3.select('#tooltip').style('visibility', 'hidden');
            })
            .on('click', (event, d) => {
                const scanDetailsUrl = `http://localhost:5173/scan/${d.scan_id}`;
                window.location.href = scanDetailsUrl;
            });

        const legend = chart.append('g')
            .attr('class', 'legend')
            .attr('transform', `translate(${width - 150},${margin.top})`);

        legend.append('path')
            .attr('d', d3.symbol().type(d3.symbolStar).size(100))
            .attr('fill', 'steelblue')
            .attr('transform', `translate(10, 0)`);

        legend.append('text')
            .attr('x', 20)
            .attr('y', 5)
            .style('font-size', '14px')
            .text('Active Scan');

        legend.append('path')
            .attr('d', d3.symbol().type(d3.symbolCircle).size(100))
            .attr('fill', 'steelblue')
            .attr('transform', `translate(10, 20)`);

        legend.append('text')
            .attr('x', 20)
            .attr('y', 25)
            .style('font-size', '14px')
            .text('Passive Scan');

        return () => {
            svg.selectAll('*').remove();
        };
    }, [data, currentScanDate]);

    return (
        <div>
            <svg ref={svgRef}></svg>
            <div id="tooltip" style={{
                position: 'absolute',
                backgroundColor: 'white',
                border: '1px solid black',
                padding: '5px',
                pointerEvents: 'none',
                visibility: 'hidden'
            }}></div>
        </div>
    );
}

RiskTimeline.propTypes = {
    scanUrl: PropTypes.string.isRequired,
    currentScanDate: PropTypes.string,
    weights: PropTypes.arrayOf(PropTypes.shape({
        owasp_name: PropTypes.string,
        weight: PropTypes.number
    })).isRequired
};

export default RiskTimeline;
