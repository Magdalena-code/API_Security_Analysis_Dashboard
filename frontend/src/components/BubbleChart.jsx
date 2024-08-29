import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';

function BubbleChart({ data }) {
    const svgRef = useRef(null);

    useEffect(() => {
        const width = 1200;
        const height = 600;
        const margin = { top: 50, right: 20, bottom: 150, left: 100 };

        const svg = d3.select(svgRef.current)
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        const xScale = d3.scaleBand()
            .domain([...new Set(data.map(d => d.category))])
            .range([0, width])
            .padding(0.3);

        const yScale = d3.scaleLinear()
            .domain([0, d3.max(data, d => d.risk)])
            .range([height, 0]);

        const sizeScale = d3.scaleSqrt()
            .domain([0, d3.max(data, d => d.occurrences)])
            .range([2, 20]); // circle size

        const colorScale = d3.scaleOrdinal(d3.schemeCategory10);

        svg.append('g')
            .attr('transform', `translate(0, ${height})`)
            .call(d3.axisBottom(xScale))
            .selectAll('text')
            .attr('transform', 'rotate(-45)')
            .style('text-anchor', 'end')
            .style('font-size', '14px');

        svg.append('g')
            .call(d3.axisLeft(yScale).ticks(10))
            .append('text')
            .attr('fill', '#000')
            .attr('transform', 'rotate(-90)')
            .attr('x', -height / 2)
            .attr('dy', '-3.5em')
            .attr('text-anchor', 'middle')
            .style('font-size', '16px')
            .text('Risk Level');

        svg.append('text')
            .attr('x', width / 2)
            .attr('y', height + margin.bottom - 20)
            .attr('text-anchor', 'middle')
            .style('font-size', '16px')
            .text('OWASP Categories');

        svg.selectAll('circle')
            .data(data)
            .enter()
            .append('circle')
            .attr('cx', d => xScale(d.category) + xScale.bandwidth() / 2)
            .attr('cy', d => yScale(d.risk))
            .attr('r', d => sizeScale(d.occurrences))
            .attr('fill', d => colorScale(d.category))
            .attr('opacity', 0.7);

        svg.selectAll('circle')
            .append('title')
            .text(d => `${d.category}\nRisk: ${d.risk}\nOccurrences: ${d.occurrences}`);

        return () => {
            d3.select(svgRef.current).selectAll('*').remove();
        };
    }, [data]);

    return (
        <div>
            <h2>OWASP Vulnerabilities Risk Visualization</h2>
            <svg ref={svgRef}></svg>
        </div>
    );
}

BubbleChart.propTypes = {
    data: PropTypes.arrayOf(
        PropTypes.shape({
            category: PropTypes.string.isRequired,
            risk: PropTypes.number.isRequired,
            occurrences: PropTypes.number.isRequired
        })
    ).isRequired
};

export default BubbleChart;
