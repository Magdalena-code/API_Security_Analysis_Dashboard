import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';

function RiskLevelBarChart({ vulnerabilities }) {
    const svgRef = useRef(null);

    useEffect(() => {
        if (!vulnerabilities || vulnerabilities.length === 0) return;

        const uniqueVulnerabilities = vulnerabilities.reduce((acc, vuln) => {
            if (!acc.find(item => item.vuln_id === vuln.vuln_id)) {
                acc.push(vuln);
            }
            return acc;
        }, []);

        const riskLevels = ['High', 'Medium', 'Low', 'Informational'];
        const riskCounts = riskLevels.map(level => ({
            risk: level,
            count: uniqueVulnerabilities.filter(vuln => vuln.prio_name === level).length,
        }));

        const margin = { top: 60, right: 20, bottom: 30, left: 60 };
        const width = 800 - margin.left - margin.right;
        const height = 400 - margin.top - margin.bottom;

        const svg = d3.select(svgRef.current)
            .attr('width', 800)
            .attr('height', 400 + margin.top + margin.bottom)
            .style('background-color', '#f0f0f0')
            .style('margin', '0 auto')
            .style('display', 'block');

        svg.selectAll('*').remove();

        const g = svg.append('g')
            .attr('transform', `translate(${margin.left},${margin.top + 20})`);  // Extra space for the title

        const x = d3.scaleBand()
            .domain(riskCounts.map(d => d.risk))
            .range([0, width])
            .padding(0.1);

        const y = d3.scaleLinear()
            .domain([0, d3.max(riskCounts, d => d.count)])
            .nice()
            .range([height, 0]);

        const xAxis = g.append('g')
            .attr('class', 'x-axis')
            .attr('transform', `translate(0,${height})`)
            .call(d3.axisBottom(x));

        xAxis.selectAll('text')
            .style('font-size', '14px')
            .attr('dy', '1em') // Add space to avoid cut-off
            .attr('transform', 'rotate(-45)')
            .style('text-anchor', 'end');

        const yAxis = g.append('g')
            .attr('class', 'y-axis')
            .call(d3.axisLeft(y).ticks(5));

        yAxis.selectAll('text')
            .style('font-size', '14px');

        const colorScale = d3.scaleOrdinal()
            .domain(riskLevels)
            .range(['#FF6347', '#FFA500', '#FFD700', '#87CEEB']);

        g.selectAll('.bar')
            .data(riskCounts)
            .enter()
            .append('rect')
            .attr('class', 'bar')
            .attr('x', d => x(d.risk))
            .attr('y', d => y(d.count))
            .attr('width', x.bandwidth())
            .attr('height', d => height - y(d.count))
            .attr('fill', d => colorScale(d.risk));

        g.selectAll('.label')
            .data(riskCounts)
            .enter()
            .append('text')
            .attr('class', 'label')
            .attr('x', d => x(d.risk) + x.bandwidth() / 2)
            .attr('y', d => y(d.count) - 5)
            .attr('text-anchor', 'middle')
            .attr('font-size', '14px')
            .text(d => d.count);

        svg.append('text')
            .attr('x', width / 2 + margin.left)
            .attr('y', margin.top - 20)
            .attr('text-anchor', 'middle')
            .attr('font-size', '20px')
            .attr('font-weight', 'bold')
            .text('Risk Level Distribution');

    }, [vulnerabilities]);

    return <svg ref={svgRef}></svg>;
}

RiskLevelBarChart.propTypes = {
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
        })
    ).isRequired,
};

export default RiskLevelBarChart;
