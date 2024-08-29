import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const API_URL = import.meta.env.VITE_API_URL;

const Customize = () => {
    const [customisations, setCustomisations] = useState([]);
    const [errorMessage, setErrorMessage] = useState('');
    const [totalWeight, setTotalWeight] = useState(0);
    const [isSaveButtonDisabled, setIsSaveButtonDisabled] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        fetchCustomisations();
    }, []);

    const fetchCustomisations = async () => {
        try {
            const response = await axios.get(`${API_URL}/customisation`);
            console.log('API response:', response.data);  // Debugging log
            setCustomisations(response.data);
            setErrorMessage('');

            // Calculate the initial total weight
            const initialTotalWeight = response.data.reduce((acc, curr) => acc + curr.weight, 0);
            setTotalWeight(initialTotalWeight);
        } catch (error) {
            console.error('Error fetching customisations:', error);
            setErrorMessage('Error fetching customisations');
        }
    };

    const handleWeightChange = (index, newWeight) => {
        const weight = Number(newWeight);

        // Calculate new total weight
        const updatedCustomisations = [...customisations];
        updatedCustomisations[index].weight = weight;

        const newTotalWeight = updatedCustomisations.reduce((acc, curr) => acc + curr.weight, 0);

        if (newTotalWeight > 100) {
            setErrorMessage('Total weight cannot exceed 100');
            setIsSaveButtonDisabled(true);
        } else {
            setErrorMessage('');
            setIsSaveButtonDisabled(false);
            setCustomisations(updatedCustomisations);
            setTotalWeight(newTotalWeight);
        }
    };

    const resetWeights = () => {
        const resetCustomisations = customisations.map(customisation => ({
            ...customisation,
            weight: 10
        }));
        setCustomisations(resetCustomisations);
        setTotalWeight(resetCustomisations.length * 10);
        setErrorMessage('');
        setIsSaveButtonDisabled(false);
    };

    const saveCustomisations = async () => {
        if (totalWeight > 100) {
            setErrorMessage('Total weight cannot exceed 100');
            return;
        }

        try {
            const response = await axios.post('http://127.0.0.1:5000/customisation', customisations);
            if (response.data.status === 'success') {
                alert('Customisations saved successfully!');
            }
        } catch (error) {
            console.error('Error saving customisations:', error);
            setErrorMessage('Error saving customisations');
        }
    };

    return (
        <div>
            <div style={{ marginBottom: '20px' }}>
                <button style={{ float: 'left' }} onClick={() => navigate('/')}>
                    Go Back to Scan Page
                </button>
                <div style={{ clear: 'both' }}></div> {/* Clear the float */}
            </div>
            <h1>Customisation</h1>
            <h2>Riskometer</h2>
            {errorMessage && <p style={{ color: 'red' }}>{errorMessage}</p>}
            <ul>
                {customisations.map((customisation, index) => (
                    <li key={`${customisation.user_id}-${customisation.owasp_cat}`}>
                        <span>{customisation.owasp_cat}</span>
                        <input
                            type="number"
                            value={customisation.weight}
                            onChange={(e) => handleWeightChange(index, e.target.value)}
                        />
                    </li>
                ))}
            </ul>
            <div>
                <p>Total weight used: {totalWeight} / 100</p>
            </div>
            <button onClick={saveCustomisations} disabled={isSaveButtonDisabled}>
                Save Changes
            </button>
            <button onClick={resetWeights} style={{ marginLeft: '10px' }}>Reset to Default</button>
        </div>
    );
};

export default Customize;
