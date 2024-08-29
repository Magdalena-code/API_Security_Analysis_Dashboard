import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL;
const BASE_URL = import.meta.env.VITE_BASE_URL;

function NewOldVulnerabilitiesChart({ scanUrl, currentScanDate }) {
    const svgRef = useRef(null);
    const [data, setData] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get(`${API_URL}/vulnerabilities?scan_url=${scanUrl}`);
                const aggregatedData = aggregateData(response.data);
                setData(aggregatedData);
            } catch (error) {
                console.error('Failed to fetch scan data:', error);
            }
        };

        fetchData();
    }, [scanUrl]);

    const aggregateData = (vulnerabilities) => {
        const scanMap = {};

        vulnerabilities.forEach(vuln => {
            const scanDate = new Date(vuln.scan_date);
            const scanDateString = scanDate.toISOString().split('T')[0]; // Convert to YYYY-MM-DD

            if (!scanMap[scanDateString]) {
                scanMap[scanDateString] = {
                    date: scanDate,
                    new_vulnerabilities: 0,
                    old_vulnerabilities: 0,
                    vuln_ids: new Set(),
                    scan_id: vuln.scan_id,
                    scan_active: vuln.scan_active
                };
            }

            if (!scanMap[scanDateString].vuln_ids.has(vuln.vuln_id)) {
                scanMap[scanDateString].vuln_ids.add(vuln.vuln_id);
                if (vuln.vuln_new) {
                    scanMap[scanDateString].new_vulnerabilities += 1;
                } else {
                    scanMap[scanDateString].old_vulnerabilities += 1;
                }
            }
        });

        return Object.values(scanMap).sort((a, b) => a.date - b.date);
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

        // Define patterns for active and passive scans
        const defs = svg.append('defs');

        defs.append('pattern')
            .attr('id', 'activePattern')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 10)
            .attr('height', 10)
            .append('path')
            .attr('d', 'M0,10 l10,-10 M-5,5 l10,-10 M5,15 l10,-10')
            .attr('stroke', 'black')
            .attr('stroke-width', 1)
            .attr('opacity', 0.3);

        defs.append('pattern')
            .attr('id', 'passivePattern')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 10)
            .attr('height', 10)
            .append('rect')
            .attr('width', 10)
            .attr('height', 10)
            .attr('fill', 'lightgray')
            .attr('opacity', 0.3);

        chart.append('text')
            .attr('x', width / 2)
            .attr('y', -10)
            .attr('text-anchor', 'middle')
            .style('font-size', '24px')
            .style('font-weight', 'bold')
            .text('New vs. Old Vulnerabilities');

        const x = d3.scaleBand()
            .domain(data.map(d => d.date.toISOString().split('T')[0]))
            .range([0, width])
            .padding(0.3);

        const y = d3.scaleLinear()
            .domain([0, d3.max(data, d => Math.max(d.new_vulnerabilities, d.old_vulnerabilities)) + 2])
            .nice()
            .range([height, 0]);

        const xAxis = d3.axisBottom(x);

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
            .style("font-size", "12px");

        chart.append('text')
            .attr('transform', 'rotate(-90)')
            .attr('y', 0 - margin.left + 10)
            .attr('x', 0 - (height / 2))
            .attr('dy', '1em')
            .style('text-anchor', 'middle')
            .style('font-size', '14px')
            .text('Number of Vulnerabilities');

        chart.selectAll('.bar.new')
            .data(data)
            .enter()
            .append('rect')
            .attr('class', 'bar new')
            .attr('x', d => x(d.date.toISOString().split('T')[0]))
            .attr('y', d => y(d.new_vulnerabilities))
            .attr('width', x.bandwidth() / 2)
            .attr('height', d => height - y(d.new_vulnerabilities))
            .attr('fill', d => d.date.toISOString().split('T')[0] === currentScanDate ? '#39FF14' : 'darkgreen')  // Highlight current scan date
            .on('click', (event, d) => {
                const scanDetailsUrl = `${BASE_URL}/scan/${d.scan_id}`;
                window.location.href = scanDetailsUrl;
            });

        chart.selectAll('.bar.old')
            .data(data)
            .enter()
            .append('rect')
            .attr('class', 'bar old')
            .attr('x', d => x(d.date.toISOString().split('T')[0]) + x.bandwidth() / 2)
            .attr('y', d => y(d.old_vulnerabilities))
            .attr('width', x.bandwidth() / 2)
            .attr('height', d => height - y(d.old_vulnerabilities))
            .attr('fill', d => d.date.toISOString().split('T')[0] === currentScanDate ? '#FF073A' : 'darkred')  // Highlight current scan date
            .on('click', (event, d) => {
                const scanDetailsUrl = `http://localhost:5173/scan/${d.scan_id}`;
                window.location.href = scanDetailsUrl;
            });

        chart.selectAll('.pattern.new')
            .data(data)
            .enter()
            .append('rect')
            .attr('class', 'pattern new')
            .attr('x', d => x(d.date.toISOString().split('T')[0]))
            .attr('y', d => y(d.new_vulnerabilities))
            .attr('width', x.bandwidth() / 2)
            .attr('height', d => height - y(d.new_vulnerabilities))
            .attr('fill', d => d.scan_active ? 'url(#activePattern)' : 'url(#passivePattern)')  // Apply pattern based on scan type
            .attr('pointer-events', 'none');

        chart.selectAll('.pattern.old')
            .data(data)
            .enter()
            .append('rect')
            .attr('class', 'pattern old')
            .attr('x', d => x(d.date.toISOString().split('T')[0]) + x.bandwidth() / 2)
            .attr('y', d => y(d.old_vulnerabilities))
            .attr('width', x.bandwidth() / 2)
            .attr('height', d => height - y(d.old_vulnerabilities))
            .attr('fill', d => d.scan_active ? 'url(#activePattern)' : 'url(#passivePattern)')
            .attr('pointer-events', 'none');


        chart.selectAll('.bar.new')
            .on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('visibility', 'visible')
                    .html(`Date: ${d.date.toLocaleDateString()}<br>New Vulnerabilities: ${d.new_vulnerabilities}`)
                    .style('left', `${event.pageX + 10}px`)
                    .style('top', `${event.pageY + 10}px`);
            })
            .on('mouseout', () => {
                d3.select('#tooltip').style('visibility', 'hidden');
            });


        chart.selectAll('.bar.old')
            .on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('visibility', 'visible')
                    .html(`Date: ${d.date.toLocaleDateString()}<br>Old Vulnerabilities: ${d.old_vulnerabilities}`)
                    .style('left', `${event.pageX + 10}px`)
                    .style('top', `${event.pageY + 10}px`);
            })
            .on('mouseout', () => {
                d3.select('#tooltip').style('visibility', 'hidden');
            });

        const legend = chart.append('g')
            .attr('class', 'legend')
            .attr('transform', `translate(${width - 150},${-20})`);

        legend.append('rect')
            .attr('x', 0)
            .attr('y', 0)
            .attr('width', 18)
            .attr('height', 18)
            .attr('fill', 'url(#activePattern)');

        legend.append('text')
            .attr('x', 24)
            .attr('y', 9)
            .attr('dy', '.35em')
            .style('font-size', '12px')
            .text('Active Scan');

        legend.append('rect')
            .attr('x', 0)
            .attr('y', 24)
            .attr('width', 18)
            .attr('height', 18)
            .attr('fill', 'url(#passivePattern)');

        legend.append('text')
            .attr('x', 24)
            .attr('y', 33)
            .attr('dy', '.35em')
            .style('font-size', '12px')
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

NewOldVulnerabilitiesChart.propTypes = {
    scanUrl: PropTypes.string.isRequired,
    currentScanDate: PropTypes.string.isRequired,
};

export default NewOldVulnerabilitiesChart;
