<?php

namespace App\Http\Controllers;

use App\Models\Project;
use App\Http\Requests\StoreProjectRequest;
use App\Http\Requests\UpdateProjectRequest;
use App\Http\Resources\ProjectResource;

class ProjectController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
{
    // Transform the projects using a resource
    $projectResource = ProjectResource::collection(Project::all());
    // Return a JSON response
    return response()->json([
        'data' => $projectResource,
    ]);
}



    /**
     * Store a newly created resource in storage.
     */
    public function store(StoreProjectRequest $request)
    {
        $data = $request->validated();
        $project = Project::create($data);


        return response()->json([
            "data" => new ProjectResource($project),
        ]);
    }


    /**
     * Display the specified resource.
     */
    public function show(Project $project)
    {
        return response()->json([
            'data' => new ProjectResource($project),
        ]);
    }


    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateProjectRequest $request, Project $project)
    {
        $data = $request->validated();
        $project->update($data);

        return response()->json([
            "data" => new ProjectResource($project),
        ]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Project $project)
    {
        $idDeleted = $project->id;
        $isdeleted = $project->delete();
        return response()->json(
             ["data" => $isdeleted ?  "Project $idDeleted deleted successfully" : "Error"]
        );
    }
}
