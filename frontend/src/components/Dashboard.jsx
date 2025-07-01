// File: src/components/Dashboard.js
import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import Navbar from './Navbar';
import { AuthContext } from '../context/AuthContext';

const Dashboard = () => {
  const [projects, setProjects] = useState([]);
  const [publicProjects, setPublicProjects] = useState([]);
  const [projectName, setProjectName] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { currentUser } = useContext(AuthContext);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      // Fetch user's projects
      const userProjectsResponse = await api.get('/projects');
      setProjects(userProjectsResponse.data);
      
      // Fetch public projects
      const publicProjectsResponse = await api.get('/projects/public');
      // Filter out user's own projects from public projects list
      const filteredPublicProjects = publicProjectsResponse.data.filter(
        project => project.user._id !== currentUser._id
      );
      setPublicProjects(filteredPublicProjects);
    } catch (err) {
      setError('Failed to fetch projects');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, [currentUser]);

  const handleCreateProject = async (e) => {
    e.preventDefault();
    
    if (!projectName.trim()) {
      return setError('Project name is required');
    }
    
    try {
      await api.post('/projects', { name: projectName, isPublic });
      setProjectName('');
      setIsPublic(false);
      fetchProjects();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create project');
      console.error(err);
    }
  };

  const handleDeleteProject = async (projectId) => {
    try {
      await api.delete(`/projects/${projectId}`);
      fetchProjects();
    } catch (err) {
      setError('Failed to delete project');
      console.error(err);
    }
  };

  return (
    <div>
      <Navbar />
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
        
        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {error}
            <button 
              className="float-right font-bold"
              onClick={() => setError('')}
            >
              &times;
            </button>
          </div>
        )}
        
        <div className="bg-white p-6 rounded shadow-md mb-6">
          <h2 className="text-xl font-semibold mb-4">Create New Project</h2>
          <form onSubmit={handleCreateProject} className="flex flex-col md:flex-row gap-4">
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="Project Name"
              className="flex-grow shadow appearance-none border rounded py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              required
            />
            
            <div className="flex items-center">
              <input
                id="isPublic"
                type="checkbox"
                checked={isPublic}
                onChange={(e) => setIsPublic(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="isPublic">Public Project</label>
            </div>
            
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
            >
              Create Project
            </button>
          </form>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white p-6 rounded shadow-md">
            <h2 className="text-xl font-semibold mb-4">My Projects</h2>
            
            {loading ? (
              <p>Loading projects...</p>
            ) : projects.length === 0 ? (
              <p>You don't have any projects yet.</p>
            ) : (
              <div className="space-y-4">
                {projects.map((project) => (
                  <div key={project._id} className="border rounded p-4 flex justify-between items-center">
                    <div>
                      <h3 className="font-medium">{project.name}</h3>
                      <p className="text-sm text-gray-500">
                        {project.isPublic ? 'Public' : 'Private'} • Created: {new Date(project.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex space-x-2">
                      <Link
                        to={`/projects/${project._id}`}
                        className="bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded text-sm"
                      >
                        View Details
                      </Link>
                      <button
                        onClick={() => handleDeleteProject(project._id)}
                        className="bg-red-600 hover:bg-red-700 text-white py-1 px-3 rounded text-sm"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          
          <div className="bg-white p-6 rounded shadow-md">
            <h2 className="text-xl font-semibold mb-4">Public Projects</h2>
            
            {loading ? (
              <p>Loading projects...</p>
            ) : publicProjects.length === 0 ? (
              <p>No public projects available.</p>
            ) : (
              <div className="space-y-4">
                {publicProjects.map((project) => (
                  <div key={project._id} className="border rounded p-4">
                    <h3 className="font-medium">{project.name}</h3>
                    <p className="text-sm text-gray-500">
                      By: {project.user.name} • Created: {new Date(project.createdAt).toLocaleDateString()}
                    </p>
                    <div className="mt-2">
                      <Link
                        to={`/projects/${project._id}`}
                        className="bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded text-sm"
                      >
                        View Details
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;