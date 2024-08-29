import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import PropTypes from 'prop-types';

function CircularPackingDiagram({ data }) {
    const svgRef = useRef(null);
    const legendRef = useRef(null);

    useEffect(() => {
        const width = 800;
        const height = 800;
        const color = d3.scaleOrdinal(d3.schemeCategory10);

        const pack = (data) => d3.pack()
            .size([width, height])
            .padding(3)
            (d3.hierarchy(data)
                .sum(d => d.value)
                .sort((a, b) => b.value - a.value));

        const root = pack(data);
        let focus = root;
        let view;

        const svg = d3.select(svgRef.current)
            .attr("viewBox", `0 0 ${width} ${height}`) // Center the visualisation
            .attr("width", width)
            .attr("height", height)
            .style("font", "14px sans-serif")
            .style("display", "block")
            .style("background", "white")
            .style("cursor", "pointer")
            .on("click", (event) => zoom(event, root));

        const node = svg.append("g")
            .attr("transform", `translate(${width / 2},${height / 2})`) // Center the circles and labels
            .selectAll("circle")
            .data(root.descendants().slice(1))
            .enter().append("circle")
            .attr("fill", d => d.children ? color(d.data.name) : "white")
            .attr("stroke", d => d.children ? "none" : "#000")
            .attr("pointer-events", d => !d.children ? "none" : null)
            .style("fill-opacity", d => d.depth === 1 ? 1 : 0)
            .attr("display", d => d.depth === 1 ? "inline" : "none")
            .on("mouseover", function () { d3.select(this).attr("stroke", "#000"); })
            .on("mouseout", function () { d3.select(this).attr("stroke", null); })
            .on("click", (event, d) => focus !== d && (zoom(event, d), event.stopPropagation()));

        const label = svg.append("g")
            .attr("transform", `translate(${width / 2},${height / 2})`) // Center the labels
            .style("font", "14px sans-serif")
            .attr("pointer-events", "none")
            .attr("text-anchor", "middle")
            .selectAll("text")
            .data(root.descendants())
            .enter().append("text")
            .style("fill-opacity", d => d.parent === root ? 1 : 0)
            .style("display", d => d.parent === root ? "inline" : "none")
            .each(function (d) {
                wrapText(d3.select(this), d.data.name, d.r);
            });

        function wrapText(text, name, radius) {
            const words = name.split(/\s+/);
            let line = [];
            let lineNumber = 0;
            const lineHeight = 1.1;
            const y = 0;
            const dy = 0;
            let tspan = text.text(null).append('tspan').attr('x', 0).attr('y', y).attr('dy', `${dy}em`);

            words.forEach((word) => {
                line.push(word);
                tspan.text(line.join(' '));
                if (tspan.node().getComputedTextLength() > 2 * radius) {
                    line.pop();
                    tspan.text(line.join(' '));
                    line = [word];
                    tspan = text.append('tspan').attr('x', 0).attr('y', y).attr('dy', `${++lineNumber * lineHeight}em`).text(word);
                }
            });
        }

        zoomTo([root.x, root.y, root.r * 2]);

        function zoomTo(v) {
            const k = width / v[2];
            view = v;
            label.attr("transform", d => `translate(${(d.x - v[0]) * k},${(d.y - v[1]) * k})`);
            node.attr("transform", d => `translate(${(d.x - v[0]) * k},${(d.y - v[1]) * k})`);
            node.attr("r", d => d.r * k);
        }

        function zoom(event, d) {
            console.log("Zoom event:", event, "Zooming to:", d.data.name);

            const focus0 = focus;
            focus = d;

            const transition = svg.transition()
                .duration(750)
                .tween("zoom", d => {
                    const i = d3.interpolateZoom(view, [focus.x, focus.y, focus.r * 2]);
                    return t => zoomTo(i(t));
                });

            label
                .filter(function (d) { return d.parent === focus || this.style.display === "inline"; })
                .transition(transition)
                .style("fill-opacity", d => d.parent === focus ? 1 : 0)
                .on("start", function (d) {
                    if (d.parent === focus) {
                        console.log("Showing label:", d.data.name);
                        this.style.display = "inline";
                        wrapText(d3.select(this), d.data.name, d.r);
                    }
                })
                .on("end", function (d) {
                    if (d.parent !== focus) {
                        console.log("Hiding label:", d.data.name);
                        this.style.display = "none";
                    }
                });

            node
                .filter(function (d) { return d.parent === focus || this.style.display === "inline"; })
                .transition(transition)
                .style("fill-opacity", d => {
                    const opacity = d.parent === focus ? 1 : 0;
                    console.log(`Setting fill-opacity for ${d.data.name}: ${opacity}`);
                    return opacity;
                })
                .attr("display", d => {
                    const display = d.parent === focus ? "inline" : "none";
                    console.log(`Setting display for ${d.data.name}: ${display}`);
                    return display;
                })
                .attr("fill", d => {
                    const fill = d.children ? color(d.data.name) : "white";
                    console.log(`Setting fill for ${d.data.name}: ${fill}`);
                    return fill;
                })
                .attr("stroke", d => {
                    const stroke = d.children ? "none" : "#000";
                    console.log(`Setting stroke for ${d.data.name}: ${stroke}`);
                    return stroke;
                })
                .on("start", function (d) {
                    if (d.parent === focus) {
                        console.log("Showing node:", d.data.name);
                        this.style.display = "inline";
                    }
                })
                .on("end", function (d) {
                    if (d.parent !== focus) {
                        console.log("Hiding node:", d.data.name);
                        this.style.display = "none";
                    }
                });
        }

        // Legend setup
        const categories = root.descendants().filter(d => d.depth === 1).map(d => d.data.name);
        const legend = d3.select(legendRef.current)
            .attr("width", 400)
            .attr("height", categories.length * 20 + 20)
            .style("display", "block")
            .style("margin", "0 auto")
            .selectAll("g")
            .data(categories)
            .enter().append("g")
            .attr("transform", (d, i) => `translate(0, ${i * 20})`);

        legend.append("rect")
            .attr("x", 0)
            .attr("y", 0)
            .attr("width", 18)
            .attr("height", 18)
            .attr("fill", d => color(d));

        legend.append("text")
            .attr("x", 24)
            .attr("y", 9)
            .attr("dy", "0.35em")
            .attr("font-size", "14px")
            .text(d => d);

        return () => {
            svg.selectAll('*').remove();
            d3.select(legendRef.current).selectAll('*').remove();
        };
    }, [data]);

    return (
        <div>
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                <h2>Number of Vulnerabilities in each OWASP Category</h2>
                <svg ref={legendRef}></svg>
            </div>
            <svg ref={svgRef} width={800} height={800}></svg>
        </div>
    );
}

CircularPackingDiagram.propTypes = {
    data: PropTypes.shape({
        name: PropTypes.string.isRequired,
        children: PropTypes.arrayOf(
            PropTypes.shape({
                name: PropTypes.string.isRequired,
                value: PropTypes.number,
                children: PropTypes.array
            })
        )
    }).isRequired
};

export default CircularPackingDiagram;
