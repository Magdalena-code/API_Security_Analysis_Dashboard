import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';

function ScatterPlot({ data }) {
    const svgRef = useRef(null);
    const legendRef = useRef(null);

    useEffect(() => {
        const width = 1600;
        const height = 600;
        const margin = { top: 50, right: 50, bottom: 400, left: 150 };

        const priorityLabels = ["Informational", "Low", "Medium", "High"];

        const svg = d3.select(svgRef.current)
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .style('background-color', '#f0f0f0')
            .append('g')
            .attr('transform', `translate(${margin.left},${margin.top})`);

        const xScale = d3.scalePoint()
            .domain(data.map(d => d.vuln_name))
            .range([0, width])
            .padding(1);

        const yScale = d3.scalePoint()
            .domain(priorityLabels)
            .range([height, 0])
            .padding(1);

        const colorScale = d3.scaleOrdinal(d3.schemeCategory10);

        svg.append('g')
            .attr('transform', `translate(0, ${height})`)
            .call(d3.axisBottom(xScale))
            .selectAll('text')
            .attr('transform', 'rotate(-45)')
            .style('text-anchor', 'end')
            .attr('dx', '-.8em')
            .attr('dy', '.15em')
            .style('font-size', '14px');

        svg.append('g')
            .call(d3.axisLeft(yScale).ticks(5))
            .selectAll('text')
            .style('font-size', '14px')
            .attr('dy', (d) => d === "Informational" ? '1.5em' : '0.35em');

        svg.append('text')
            .attr('fill', '#000')
            .attr('transform', 'rotate(-90)')
            .attr('x', -height / 2)
            .attr('dy', '-3.5em')
            .attr('text-anchor', 'middle')
            .text('Risk Level')
            .style('font-size', '16px');

        const arc = d3.arc()
            .outerRadius(15)
            .innerRadius(0);

        const pie = d3.pie()
            .value(1);

        const sliceGroups = svg.selectAll('.slice')
            .data(data)
            .enter()
            .append('g')
            .attr('class', 'slice')
            .attr('transform', d => `translate(${xScale(d.vuln_name)},${yScale(priorityLabels[d.priority - 1])})`);

        sliceGroups.selectAll('path')
            .data(d => pie(d.owasp_names))
            .enter()
            .append('path')
            .attr('d', arc)
            .attr('fill', d => colorScale(d.data));

        sliceGroups.append('title')
            .text(d => `${d.vuln_name}\nPriority: ${priorityLabels[d.priority - 1]}\nCategories: ${d.owasp_names.join(', ')}`);


        const legendData = Array.from(new Set(data.flatMap(d => d.owasp_names)));

        const legend = d3.select(legendRef.current)
            .attr('width', 400)
            .attr('height', legendData.length * 25)
            .style("display", "block")
            .style("margin", "0 auto")
            .append('g')
            .attr('class', 'legend');

        legend.selectAll('rect')
            .data(legendData)
            .enter()
            .append('rect')
            .attr('x', 0)
            .attr('y', (d, i) => i * 25)
            .attr('width', 18)
            .attr('height', 18)
            .style('fill', colorScale);

        legend.selectAll('text')
            .data(legendData)
            .enter()
            .append('text')
            .attr('x', 24)
            .attr('y', (d, i) => i * 25 + 9)
            .attr('dy', '.35em')
            .style('text-anchor', 'start')
            .style('font-size', '14px')
            .text(d => d);

        return () => {
            svg.selectAll('*').remove();
            d3.select(legendRef.current).selectAll('*').remove();
        };
    }, [data]);

    return (
        <div>
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                <h2>Risk Level Scatter Plot</h2>
                <svg ref={legendRef}></svg>
            </div>
            <svg ref={svgRef}></svg>
        </div>
    );
}

ScatterPlot.propTypes = {
    data: PropTypes.arrayOf(
        PropTypes.shape({
            vuln_name: PropTypes.string.isRequired,
            priority: PropTypes.number.isRequired,
            owasp_names: PropTypes.arrayOf(PropTypes.string).isRequired
        })
    ).isRequired
};

export default ScatterPlot;
