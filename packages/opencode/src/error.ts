export abstract class SageVerdictError extends Error {
	constructor(message: string, name?: string) {
		super(message);
		this.name = name ?? "SageVerdictError";
	}
}

export class SageVerdictBlockError extends SageVerdictError {
	constructor(message: string) {
		super(message, "SageVerdictBlockError");
	}
}
