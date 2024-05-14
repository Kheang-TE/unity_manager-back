/* eslint-disable max-len */
import Joi from "joi";
import { Project } from "../models/index.js";

/**
 * Retrieves all projects from the database and sends them as a JSON response.
 *
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing all available projects or an error message if no projects are found.
 */

export async function getAllProjects(req, res) {
  const projects = await Project.find();
  if (!projects) {
    return res.status(404).json({ error: "Projects not found" });
  }
  res.json(projects);
}

/**
 * Retrieves a single project based on the provided ID.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} The project object or an error message
 */
export async function getOneProject(req, res) {
  const { error } = Joi.number().integer().greater(0).validate(req.params.id);
  if (error) {
    return res
      .status(400)
      .json({
        error: `Card not found. Verify the provided ID. ${error.message}`,
      });
  }
  const projectId = +req.params.id;
  const project = await Project.findByPk(projectId);
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }
  res.json(project);
}

/**
 * Creates a new project based on the provided request body, validates the input data, checks if the owner exists, and saves the project to the database.
 *
 * @param {Object} req - The request object containing the project data.
 * @param {Object} res - The response object to send the result.
 * @return {Object} The newly created project object or an error message.
 */
export async function createProject(req, res) {
  const createProjectSchema = Joi.object({
    name: Joi.string().required(),
    ownerId: Joi.number().integer().greater(0).required(),
  });
  const { error } = createProjectSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }
  const { name, owner_Id } = req.body;
  if (!name) {
    return res.status(404).json({ error: "The provided name does not exist" });
  }
  const createNewProject = await Project.create({
    name,
    owner_Id,
  });
  res.status(201).json(createNewProject);
}

/**
 * Deletes a project from the database based on its ID.
 *
 * @param {Object} req - The HTTP request object containing the ID of the project to delete.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A 204 No Content response if the deletion is successful, or an error message if the project is not found.
 */
export async function deleteProject(req, res) {
  const projectId = +req.params.id;
  if (!Number.isInteger(projectId)) {
    return res.status(400).json({ error: "Project not found" });
  }
  const project = await Project.findByPk(projectId);
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }
  await project.destroy();
  res.status(204).end();
}

/**
 * Updates a project in the database by its ID and sends the updated project as a JSON response.
 *
 * @param {Object} req - The HTTP request object containing the ID of the project to update and the updated project data.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>} A JSON object containing the updated project or an error message if the update fails.
 */
export async function updateProject(req, res) {
  const projectId = +req.params.id;
  if (!Number.isInteger(projectId)) {
    return res.status(400).json({ error: "Project not found" });
  }
  const UpdateProjectSchema = Joi.object({
    name: Joi.string(),
    owner_Id: Joi.number().integer().greater(0),
  });
  const { error } = UpdateProjectSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.message });
  }

  const { name, owner_Id } = req.body;

  const project = await Project.findByPk(projectId);

  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }

  if (owner_Id) {
    const owner = await Project.findByPk(owner_Id);
    if (!owner) {
      return res.status(404).json({ error: "Owner not found" });
    }
  }
  const updatedProject = await project.update({
    name,
    owner_Id,
  });
  res.json(updatedProject);
}
