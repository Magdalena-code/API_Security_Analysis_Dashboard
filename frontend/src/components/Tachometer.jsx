import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';

function Tachometer({ vulnerabilities, weights }) {
    const svgRef = useRef(null);

    const filterUniqueVulnerabilities = (vulnerabilities, weights = []) => {
        const weightMapping = {};
        weights.forEach(weight => {
            const owaspName = weight.owasp_name ? weight.owasp_name.toLowerCase() : 'informational';
            weightMapping[owaspName] = weight.weight;
        });

        const uniqueVulnMap = {};
        vulnerabilities.forEach(vuln => {
            const owaspName = vuln.owasp_name ? vuln.owasp_name.toLowerCase() : 'informational';
            const currentWeight = weightMapping[owaspName] || 0;

            if (uniqueVulnMap[vuln.vuln_id]) {
                const existingWeight = uniqueVulnMap[vuln.vuln_id].highestWeight || 0;
                if (currentWeight > existingWeight) {
                    uniqueVulnMap[vuln.vuln_id] = { ...vuln, highestWeight: currentWeight };
                }
            } else {
                uniqueVulnMap[vuln.vuln_id] = { ...vuln, highestWeight: currentWeight };
            }
        });

        return Object.values(uniqueVulnMap);
    };

    const calculateRiskScore = (vulnerability) => {
        const priorityOrder = { 'high': 4, 'medium': 3, 'low': 2, 'informational': 1 };
        const priority = priorityOrder[vulnerability.prio_name ? vulnerability.prio_name.toLowerCase() : 'informational'] || 0;
        const weight = vulnerability.highestWeight || 0;

        return priority * weight;
    };

    useEffect(() => {
        const width = 600;
        const height = 400;
        const arcMin = Math.PI / 2;
        const arcMax = -Math.PI / 2;

        const uniqueVulnerabilities = filterUniqueVulnerabilities(vulnerabilities, weights);

        const totalBaseRiskScore = uniqueVulnerabilities.reduce((total, vuln) => {
            return total + calculateRiskScore(vuln);
        }, 0);

        const scalingFactor = 1 + (uniqueVulnerabilities.length - 1) * 0.5;

// Adjusted risk score with scaling factor so that the more vulnerabilities the higher the risk score is
        const adjustedRiskScore = totalBaseRiskScore * scalingFactor;

        const maxPriority = 4;
        const maxWeight = 100;
        const maxPossibleBaseScore = uniqueVulnerabilities.length * maxPriority * maxWeight;

        const normalizedRiskScore = (adjustedRiskScore / maxPossibleBaseScore);


        const needleAngle = arcMin + (arcMax - arcMin) * normalizedRiskScore;

        const arc = d3.arc()
            .innerRadius(120)
            .outerRadius(150)
            .startAngle(d => arcMin + (arcMax - arcMin) * d[0])
            .endAngle(d => arcMin + (arcMax - arcMin) * d[1]);

        const svg = d3.select(svgRef.current)
            .attr('width', width)
            .attr('height', height);

        svg.selectAll('*').remove();

        const mainGroup = svg.append('g')
            .attr('transform', `translate(${width / 2},${height * 0.65})`);

        const arcsGroup = mainGroup.append('g');
        const needleGroup = mainGroup.append('g');
        const labelGroup = mainGroup.append('g');
        const percentageGroup = svg.append('g');

        const colorBands = [
            { range: [0, 0.25], color: 'green' },
            { range: [0.25, 0.5], color: 'yellow' },
            { range: [0.5, 0.75], color: 'orange' },
            { range: [0.75, 1], color: 'red' },
        ];

        colorBands.forEach(band => {
            arcsGroup.append('path')
                .datum(band.range)
                .style('fill', band.color)
                .attr('d', arc);
        });

        const labels = [
            { label: 'High', angle: arcMin + (arcMax - arcMin) * -0.4 },
            { label: 'Low', angle: arcMin + (arcMax - arcMin) * 0.4 },
        ];

        labels.forEach(label => {
            arcsGroup.append('text')
                .attr('x', Math.cos(label.angle) * 170)
                .attr('y', Math.sin(label.angle) * 170)
                .attr('text-anchor', 'middle')
                .attr('alignment-baseline', 'middle')
                .style('font-size', '14px')
                .style('font-weight', 'bold')
                .text(label.label);
        });

        // Needle
        needleGroup.append('line')
            .attr('x1', 0)
            .attr('y1', 0)
            .attr('x2', 0)
            .attr('y2', -110)
            .attr('stroke', 'black')
            .attr('stroke-width', 3)
            .attr('transform', `rotate(${needleAngle * 180 / Math.PI})`);


        labelGroup.append('text')
            .attr('x', 0)
            .attr('y', 40)
            .attr('text-anchor', 'middle')
            .style('font-size', '24px')
            .style('font-weight', 'bold')
            .text('Riskometer');


        const percentageText = `${(normalizedRiskScore * 100).toFixed(2)}%`;
        percentageGroup.append('text')
            .attr('x', width / 2)
            .attr('y', height * 0.2)
            .attr('text-anchor', 'middle')
            .style('font-size', '20px')
            .style('font-weight', 'bold')
            .text(percentageText);
    }, [vulnerabilities, weights]);

    return (
        <svg ref={svgRef}></svg>
    );
}

Tachometer.propTypes = {
    vulnerabilities: PropTypes.arrayOf(
        PropTypes.shape({
            prio_name: PropTypes.string.isRequired,
            owasp_name: PropTypes.string.isRequired,
            vuln_id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
            scan_date: PropTypes.string.isRequired,
        })
    ).isRequired,
    weights: PropTypes.arrayOf(
        PropTypes.shape({
            user_id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
            owasp_name: PropTypes.string.isRequired,
            weight: PropTypes.number.isRequired,
        })
    ).isRequired,
};

export default Tachometer;
