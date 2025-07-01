import React, { useState, useEffect, useRef } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import Editor from "@monaco-editor/react";
import api from "../services/api";
import Navbar from "./Navbar";
import { io } from "socket.io-client";

const ProjectIDE = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [requesting, setRequesting] = useState(false);
  const [accessRequested, setAccessRequested] = useState(false);
  const [userCanEdit, setUserCanEdit] = useState(false);
  const [activeUsers, setActiveUsers] = useState({});
  const [currentUser, setCurrentUser] = useState(null);
  const [isCreatingFile, setIsCreatingFile] = useState(false);
  const [newFileName, setNewFileName] = useState("");
  const [currentBranch, setCurrentBranch] = useState("main");

  const [threatScanning, setThreatScanning] = useState(false);
  const [threatResults, setThreatResults] = useState(null);

  const socketRef = useRef(null);
  const editorRef = useRef(null);
  const contentChangeTimeoutRef = useRef(null);



  // Connect to Socket.IO server
  useEffect(() => {
    const socket = io(process.env.REACT_APP_API_URL || "http://localhost:5000");
    socketRef.current = socket;

    socket.on("connect", () => {
      console.log("Connected to Socket.IO server");
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from Socket.IO server");
    });

    socket.on("user_joined", (data) => {
      setActiveUsers(data.active_users);
    });

    socket.on("user_left", (data) => {
      setActiveUsers(data.active_users);
    });

    socket.on("content_changed", (data) => {
      // Only update content if it's from another user
      if (data.user_id !== currentUser?._id) {
        setFileContent(data.content);
        if (editorRef.current) {
          editorRef.current.setValue(data.content);
        }
      }
    });

    return () => {
      // Clean up socket connection
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  // Fetch project details and current user
  useEffect(() => {
    const fetchProjectDetails = async () => {
      try {
        setLoading(true);
        const projectResponse = await api.get(`/projects/${projectId}`);
        setProject(projectResponse.data);

        // Check if user has edit rights
        const userResponse = await api.get("/users/me");
        setCurrentUser(userResponse.data);

        const canEdit =
          projectResponse.data.user_id === userResponse.data._id ||
          projectResponse.data.allowedEditors?.includes(userResponse.data._id);

        setUserCanEdit(canEdit);
        setAccessRequested(
          projectResponse.data.accessRequests?.includes(userResponse.data._id)
        );

        const filesResponse = await api.get(`/projects/${projectId}/files`);
        setFiles(filesResponse.data);

        // Get current branch
        try {
          const branchesResponse = await api.get(
            `/projects/${projectId}/branches`
          );
          // Find current branch (HEAD)
          const currentBranch = branchesResponse.data.branches.find(
            (b) => b.isCurrent
          );
          if (currentBranch) {
            setCurrentBranch(currentBranch.name);
          }
        } catch (err) {
          console.error("Failed to fetch branches", err);
        }
      } catch (err) {
        setError("Failed to fetch project details");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchProjectDetails();
  }, [projectId]);

  // Join/leave file room when selecting files
  useEffect(() => {
    if (selectedFile && currentUser && socketRef.current) {
      // Join the room for this file
      socketRef.current.emit("join_file", {
        project_id: projectId,
        file_name: selectedFile,
        user_id: currentUser._id,
        user_name: currentUser.name,
      });

      // Leave the room when unmounting or changing files
      return () => {
        socketRef.current.emit("leave_file", {
          project_id: projectId,
          file_name: selectedFile,
          user_id: currentUser._id,
        });
      };
    }
  }, [selectedFile, currentUser, projectId]);

  const handleFileSelect = async (fileName) => {
    try {
      setSelectedFile(fileName);
      const response = await api.get(
        `/projects/${projectId}/files/${encodeURIComponent(fileName)}/content`
      );
      setFileContent(response.data.content);
    } catch (err) {
      setError(`Failed to load file content: ${err.message}`);
    }
  };

  const handleEditorChange = (value) => {
    setFileContent(value);

    // Emit content change to other users with debounce
    if (socketRef.current && currentUser) {
      if (contentChangeTimeoutRef.current) {
        clearTimeout(contentChangeTimeoutRef.current);
      }

      contentChangeTimeoutRef.current = setTimeout(() => {
        socketRef.current.emit("content_change", {
          project_id: projectId,
          file_name: selectedFile,
          content: value,
          user_id: currentUser._id,
        });
      }, 3000); // Debounce time: 500ms
    }
  };

  const handleSaveFile = async () => {
    if (!selectedFile || !userCanEdit) return;

    try {
      setSaving(true);
      await api.post(
        `/projects/${projectId}/files/${encodeURIComponent(selectedFile)}/save`,
        {
          content: fileContent,
        }
      );
      setSaving(false);
    } catch (err) {
      setError(`Failed to save file: ${err.message}`);
      setSaving(false);
    }
  };


  
// Add this function to the ProjectIDE component
const downloadProject = async () => {
  try {
    // Create a "downloading" state if you want to show a loading indicator
    const response = await api.get(`/projects/${projectId}/download`, {
      responseType: 'blob' // Important: this tells axios to treat the response as binary data
    });
    
    // Create a blob URL from the response data
    const blob = new Blob([response.data], { type: 'application/zip' });
    const url = window.URL.createObjectURL(blob);
    
    // Create a temporary anchor element and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = `${project.name}.zip`; // Use project name for the file
    document.body.appendChild(a);
    a.click();
    
    // Clean up
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (err) {
    console.error("Download error:", err);
    setError(`Failed to download project: ${err.message || 'Unknown error'}`);
  }
};

  const handleEditorMount = (editor) => {
    editorRef.current = editor;
  };

  const requestAccess = async () => {
    try {
      setRequesting(true);
      await api.post(`/projects/${projectId}/access-request`);
      setAccessRequested(true);
    } catch (err) {
      setError(`Failed to request access: ${err.message}`);
    } finally {
      setRequesting(false);
    }
  };

  const handleCreateNewFile = async () => {
    if (!newFileName.trim()) {
      setError("File name cannot be empty");
      return;
    }

    try {
      const response = await api.post(`/projects/${projectId}/files`, {
        fileName: newFileName,
        content: "",
      });

      // Add new file to files list
      setFiles([...files, response.data]);

      // Select the new file
      setSelectedFile(response.data.name);
      setFileContent("");

      // Reset form
      setNewFileName("");
      setIsCreatingFile(false);
    } catch (err) {
      setError(
        `Failed to create file: ${err.response?.data?.message || err.message}`
      );
    }
  };

  const checkForThreats = async () => {
    try {
      setThreatScanning(true);
      setThreatResults(null);
      const response = await api.get(`/projects/${projectId}/threat-check`);
      setThreatResults(response.data);
    } catch (err) {
      setError(`Failed to scan for threats: ${err.message}`);
    } finally {
      setThreatScanning(false);
    }
  };

  // Determine appropriate language mode for Monaco editor
  const getLanguageFromFilename = (filename) => {
    if (!filename) return "plaintext";
    const ext = filename.split(".").pop().toLowerCase();
    const langMap = {
      js: "javascript",
      jsx: "javascript",
      ts: "typescript",
      tsx: "typescript",
      py: "python",
      html: "html",
      css: "css",
      json: "json",
      md: "markdown",
      php: "php",
      c: "c",
      cpp: "cpp",
      h: "cpp",
      java: "java",
      go: "go",
      rs: "rust",
      sh: "shell",
      yml: "yaml",
      yaml: "yaml",
    };
    return langMap[ext] || "plaintext";
  };

  if (loading) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="flex items-center justify-center h-64">
            <p>Loading project IDE...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {error}
          </div>
          <Link
            to={`/projects/${projectId}`}
            className="text-blue-600 hover:text-blue-800"
          >
            &larr; Back to Project
          </Link>
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-4">
            Project not found or you don't have permission to view it.
          </div>
          <Link to="/dashboard" className="text-blue-600 hover:text-blue-800">
            &larr; Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen">
      <Navbar />
      <div className="flex-1 flex">
        {/* File Explorer Sidebar */}
        <div className="w-64 bg-gray-100 border-r overflow-y-auto">
          <div className="p-4">
            <Link
              to={`/projects/${projectId}`}
              className="text-blue-600 hover:text-blue-800 block mb-4"
            >
              &larr; Back to Project
            </Link>
            <div className="flex items-center justify-between mb-2">
              <h2 className="font-bold text-lg">{project.name}</h2>
              <span className="text-xs bg-gray-200 px-2 py-1 rounded">
                {currentBranch}
              </span>
            </div>

            {userCanEdit && (
              <div className="mb-4">
                {isCreatingFile ? (
                  <div className="mt-2 space-y-2">
                    <input
                      type="text"
                      className="w-full px-2 py-1 border rounded"
                      placeholder="File name"
                      value={newFileName}
                      onChange={(e) => setNewFileName(e.target.value)}
                    />
                    <div className="flex space-x-2">
                      <button
                        className="bg-green-500 hover:bg-green-600 text-white px-2 py-1 rounded text-sm"
                        onClick={handleCreateNewFile}
                      >
                        Create
                      </button>
                      <button
                        className="bg-gray-300 hover:bg-gray-400 text-gray-800 px-2 py-1 rounded text-sm"
                        onClick={() => {
                          setIsCreatingFile(false);
                          setNewFileName("");
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm w-full"
                    onClick={() => setIsCreatingFile(true)}
                  >
                    Create New File
                  </button>
                )}
              </div>
            )}
            {userCanEdit && (
              <div className="mb-4 mt-2">
                <button
                  className="bg-yellow-500 hover:bg-yellow-600 text-white px-3 py-1 rounded text-sm w-full flex items-center justify-center"
                  onClick={checkForThreats}
                  disabled={threatScanning}
                >
                  {threatScanning ? (
                    <span className="flex items-center">
                      <svg
                        className="animate-spin -ml-1 mr-2 h-4 w-4 text-white"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        ></circle>
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        ></path>
                      </svg>
                      Scanning...
                    </span>
                  ) : (
                    <>
                      <svg
                        className="w-4 h-4 mr-2"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                        ></path>
                      </svg>
                      Threat Intelligence Check
                    </>
                  )}
                </button>
              </div>
            )}
            {/* Download Project Button */}
<div className="mb-4">
  <button
    className="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded text-sm w-full flex items-center justify-center"
    onClick={downloadProject}
  >
    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
    </svg>
    Clone Project
  </button>
</div>
            <div className="mb-2">Files:</div>
            {files.length === 0 ? (
              <p className="text-gray-500">No files in this project</p>
            ) : (
              <ul className="space-y-1">
                {files.map((file) => (
                  <li
                    key={file.name}
                    className={`p-2 rounded cursor-pointer hover:bg-gray-200 ${
                      selectedFile === file.name ? "bg-gray-300" : ""
                    }`}
                    onClick={() => handleFileSelect(file.name)}
                  >
                    <div className="flex items-center">
                      <svg
                        className="w-4 h-4 text-gray-500 mr-2"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                        ></path>
                      </svg>
                      <span className="text-sm truncate">{file.name}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {threatResults && (
            <div className="mt-4 border-t pt-4">
              <h3 className="font-medium mb-2">Threat Scan Results</h3>
              <div
                className={`px-3 py-2 rounded mb-2 text-sm ${
                  threatResults.total_threats > 0
                    ? "bg-red-100 text-red-800"
                    : "bg-green-100 text-green-800"
                }`}
              >
                <div className="font-medium">
                  {threatResults.total_threats > 0
                    ? `⚠️ ${threatResults.total_threats} threat${
                        threatResults.total_threats !== 1 ? "s" : ""
                      } found`
                    : "✅ No threats found"}
                </div>
                <div className="text-xs mt-1">
                  Scanned {threatResults.files_scanned} file
                  {threatResults.files_scanned !== 1 ? "s" : ""}
                </div>
              </div>

              {threatResults.results.length > 0 && (
                <div className="mt-2 max-h-48 overflow-y-auto">
                  {threatResults.results.map((result, idx) => (
                    <div
                      key={idx}
                      className="mb-2 bg-gray-50 p-2 rounded border border-gray-200"
                    >
                      <div className="font-medium text-sm truncate">
                        {result.filename}
                      </div>
                      <ul className="mt-1">
                        {result.threats.map((threat, tidx) => (
                          <li
                          key={tidx}
                          className="text-xs py-1 border-t border-gray-100"
                        >
                          <span
                            className={`inline-block px-1 rounded text-white mr-1 ${
                              threat.type === "Vulnerability"
                                ? "bg-red-600"
                                : threat.type === "Malicious IP"
                                ? "bg-orange-500"
                                : threat.type === "IOC"
                                ? "bg-purple-500"
                                : threat.type === "Hardcoded Credential"
                                ? "bg-pink-600"
                                : threat.type === "XSS Vulnerability" 
                                ? "bg-yellow-600"
                                : threat.type === "SQL Injection"
                                ? "bg-red-800"
                                : "bg-blue-500"
                            }`}
                          >
                            {threat.type}
                          </span>
                          <span className="font-medium">
                            {threat.indicator}
                          </span>
                          {threat.severity && (
                            <span
                              className={`ml-1 text-xs px-1 rounded ${
                                threat.severity === "CRITICAL"
                                  ? "bg-red-100 text-red-800"
                                  : threat.severity === "HIGH"
                                  ? "bg-orange-100 text-orange-800"
                                  : threat.severity === "MEDIUM"
                                  ? "bg-yellow-100 text-yellow-800"
                                  : "bg-blue-100 text-blue-800"
                              }`}
                            >
                              {threat.severity}
                            </span>
                          )}
                          {threat.cvss_score && (
                            <span className="ml-1">
                              ({threat.cvss_score})
                            </span>
                          )}
                        </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        

        {/* Editor Area */}
        <div className="flex-1 flex flex-col">
          {!userCanEdit && !project.isPublic && (
            <div className="bg-yellow-100 border-b border-yellow-300 p-4">
              <p className="text-yellow-700 font-medium">
                You don't have edit access to this project.
              </p>
            </div>
          )}

          {!userCanEdit && project.isPublic && !accessRequested && (
            <div className="bg-blue-100 border-b border-blue-300 p-4 flex justify-between items-center">
              <p className="text-blue-700">
                This is a public project. You need to request edit access.
              </p>
              <button
                onClick={requestAccess}
                disabled={requesting}
                className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm disabled:opacity-50"
              >
                {requesting ? "Requesting..." : "Request Access"}
              </button>
            </div>
          )}

          {accessRequested && (
            <div className="bg-green-100 border-b border-green-300 p-4">
              <p className="text-green-700">
                Access requested. Waiting for the project owner to approve.
              </p>
            </div>
          )}

          {selectedFile ? (
            <>
              <div className="bg-gray-100 border-b p-3 flex justify-between items-center">
                <div className="flex items-center">
                  <div className="font-medium mr-4">{selectedFile}</div>
                  {/* Active Users Display */}
                  <div className="flex">
                    {Object.entries(activeUsers).map(([userId, userName]) => (
                      <div
                        key={userId}
                        className="flex items-center bg-blue-100 rounded-full px-3 py-1 text-xs mx-1"
                        title={userName}
                      >
                        <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        <span>{userName}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {userCanEdit && (
                  <button
                    onClick={handleSaveFile}
                    disabled={saving}
                    className="bg-green-500 hover:bg-green-600 text-white px-4 py-1 rounded disabled:opacity-50"
                  >
                    {saving ? "Saving..." : "Save"}
                  </button>
                )}
              </div>
              <div className="flex-1">
                <Editor
                  height="100%"
                  defaultLanguage={getLanguageFromFilename(selectedFile)}
                  value={fileContent}
                  onChange={handleEditorChange}
                  onMount={handleEditorMount}
                  options={{
                    readOnly: !userCanEdit,
                    minimap: { enabled: true },
                    automaticLayout: true,
                    scrollBeyondLastLine: false,
                  }}
                  theme="vs-dark"
                />
              </div>
            </>
          ) : (
            <div className="flex flex-1 items-center justify-center bg-gray-50">
              <div className="text-gray-500 text-center">
                <svg
                  className="w-16 h-16 mx-auto mb-4 text-gray-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  ></path>
                </svg>
                <p>Select a file from the sidebar to edit</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProjectIDE;
