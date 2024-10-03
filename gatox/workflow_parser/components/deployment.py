
class Deployment():

    FIXED = "Fixed"

    def __init__(self, deployment: str):

        deployments = deployment

        _needs_resolution = False
       

    
    def _get_type(self, deployment_capture):

        if '${{' in deployment:
            # Context
            
            if '||' in deployment or '&&' in deployment:
                # We have an expression, need to parse.
                pass
            elif '.' in deployment:

                if 'inputs.' in deployment:
                    # Resolve input
                    pass
                
                elif 'needs' in deployment:
                    # Resolve based on job
                    p
                else:
                    # Unknown, grab the last segment and
                    # match against envs. Fail open
                    # if inconclusive.
                    pass
                
        else:
            deployment = deployment_capture[0]
        

            return self.FIXED
    
        
    def is_resolved(self):
        return not self._needs_resolution